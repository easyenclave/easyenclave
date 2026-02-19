"""Authentication and billing route registration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from .db_models import AdminSession
from .models import (
    Account,
    AccountCreateRequest,
    AccountLinkIdentityRequest,
    AccountListResponse,
    AccountResponse,
    AdminLoginRequest,
    AdminLoginResponse,
    AgentCapacityReconcileRequest,
    AgentCapacityReconcileResponse,
    AgentCapacityTarget,
    ApiKeyRotateResponse,
    CapacityLaunchOrderListResponse,
    CapacityPurchaseRequest,
    CapacityPurchaseResponse,
    CreatePaymentIntentRequest,
    DepositRequest,
    RateCardResponse,
    TransactionListResponse,
    TransactionResponse,
)
from .oauth import is_github_oauth_configured

RATE_CARD: dict[str, float] = {
    "cpu_per_vcpu_hr": 0.04,
    "memory_per_gb_hr": 0.005,
    "gpu_per_gpu_hr": 0.50,
    "storage_per_gb_mo": 0.10,
}


def register_auth_billing_routes(
    app: FastAPI,
    *,
    logger: Any,
    verify_admin_token: Callable[..., Any],
    require_admin_session: Callable[..., Any],
    verify_account_api_key: Callable[..., Any],
    is_admin_session: Callable[[AdminSession], bool],
    password_login_allowed_fn: Callable[[], bool],
    get_admin_password_hash_fn: Callable[[], str],
    generated_admin_password_fn: Callable[[], str | None],
    verify_password_fn: Callable[[str, str], bool],
    generate_session_token_fn: Callable[[], str],
    create_session_expiry_fn: Callable[..., datetime],
    hash_api_key_fn: Callable[[str], str],
    get_token_prefix_fn: Callable[[str], str],
    generate_api_key_fn: Callable[[str], str],
    get_key_prefix_fn: Callable[[str], str],
    admin_session_store: Any,
    account_store: Any,
    transaction_store: Any,
    capacity_pool_target_store: Any,
    capacity_launch_order_store: Any,
    agent_store: Any,
    build_filters_fn: Callable[..., dict | None],
    create_transaction_fn: Callable[..., Any],
    get_or_404_fn: Callable[[Any, str, str], Any],
    normalize_registration_datacenter_fn: Callable[[str], str],
    datacenter_re: Any,
    normalize_registration_node_size_fn: Callable[[str], str],
    parse_bool_setting_fn: Callable[[str, bool], bool],
    get_setting_fn: Callable[[str], str],
    capacity_unit_price_monthly_usd_fn: Callable[[str], float],
    reconcile_agent_capacity_fn: Callable[..., Awaitable[AgentCapacityReconcileResponse]],
    capacity_pool_target_view_fn: Callable[..., Any],
    capacity_launch_order_view_fn: Callable[[Any], Any],
) -> None:
    """Register auth and billing routes."""

    @app.post("/admin/login", response_model=AdminLoginResponse)
    async def admin_login(request: AdminLoginRequest, req: Request):
        """Admin login endpoint - creates a session token."""
        if not password_login_allowed_fn():
            raise HTTPException(
                status_code=403, detail="Password login is disabled. Use GitHub OAuth."
            )

        password_hash = get_admin_password_hash_fn()
        if not password_hash:
            raise HTTPException(
                status_code=403, detail="Password login is not configured. Use GitHub OAuth."
            )

        if not verify_password_fn(request.password, password_hash):
            logger.warning(
                f"Failed admin login attempt from {req.client.host if req.client else 'unknown'}"
            )
            raise HTTPException(status_code=401, detail="Invalid password")

        token = generate_session_token_fn()
        token_hash_val = hash_api_key_fn(token)
        token_prefix = get_token_prefix_fn(token)
        expires_at = create_session_expiry_fn(hours=24)

        session = AdminSession(
            token_hash=token_hash_val,
            token_prefix=token_prefix,
            expires_at=expires_at,
            ip_address=req.client.host if req.client else None,
        )
        admin_session_store.create(session)
        logger.info(f"Admin logged in from {req.client.host if req.client else 'unknown'}")
        return AdminLoginResponse(token=token, expires_at=expires_at)

    @app.get("/auth/methods")
    async def auth_methods():
        """Return which login methods are available (public, no auth required)."""
        password_enabled = bool(password_login_allowed_fn() and get_admin_password_hash_fn())
        github_enabled = is_github_oauth_configured()
        result = {"password": password_enabled, "github": github_enabled}
        generated_password = generated_admin_password_fn()
        if password_enabled and generated_password:
            result["generated_password"] = generated_password
        return result

    @app.get("/auth/github")
    async def github_oauth_start():
        """Initiate GitHub OAuth flow for admin login."""
        from .oauth import _client_id, create_oauth_state, get_github_authorize_url

        if not _client_id():
            raise HTTPException(
                status_code=503,
                detail="GitHub OAuth not configured. Set GITHUB_OAUTH_CLIENT_ID.",
            )

        state = create_oauth_state()
        auth_url = get_github_authorize_url(state)
        return {"auth_url": auth_url, "state": state}

    @app.get("/auth/github/callback")
    async def github_oauth_callback(
        code: str,
        state: str,
        req: Request,
    ):
        """Handle GitHub OAuth callback and create admin session."""
        from fastapi.responses import RedirectResponse

        from .oauth import (
            exchange_code_for_token,
            get_github_user,
            get_github_user_orgs,
            verify_oauth_state,
        )

        if not verify_oauth_state(state):
            raise HTTPException(status_code=400, detail="Invalid or expired state token")

        try:
            access_token = await exchange_code_for_token(code)
            user_info = await get_github_user(access_token)
        except Exception as exc:
            logger.error(f"GitHub OAuth error: {exc}")
            raise HTTPException(status_code=400, detail="GitHub authentication failed") from exc

        try:
            github_orgs = await get_github_user_orgs(access_token)
        except Exception as exc:
            logger.warning(f"Failed to fetch GitHub orgs: {exc}")
            github_orgs = []

        token = generate_session_token_fn()
        expires_at = create_session_expiry_fn(hours=24)
        session = AdminSession(
            token_hash=hash_api_key_fn(token),
            token_prefix=get_token_prefix_fn(token),
            expires_at=expires_at,
            ip_address=req.client.host if req.client else None,
            github_id=user_info["github_id"],
            github_login=user_info["github_login"],
            github_email=user_info["github_email"],
            github_avatar_url=user_info.get("github_avatar_url"),
            auth_method="github_oauth",
            github_orgs=github_orgs or None,
        )
        admin_session_store.create(session)
        logger.info(
            "Admin logged in via GitHub: %s from %s",
            user_info["github_login"],
            req.client.host if req.client else "unknown",
        )
        return RedirectResponse(url=f"/admin?token={token}", status_code=302)

    @app.get("/auth/me")
    async def get_current_user(session: AdminSession = Depends(verify_admin_token)):
        """Get current authenticated admin user info."""
        return {
            "authenticated": True,
            "auth_method": session.auth_method,
            "is_admin": is_admin_session(session),
            "github_login": session.github_login,
            "github_email": session.github_email,
            "github_avatar_url": session.github_avatar_url,
            "github_orgs": session.github_orgs or [],
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
        }

    @app.post("/api/v1/accounts")
    async def create_account(request: AccountCreateRequest):
        """Create a new billing account and return API key (only shown once)."""
        if request.account_type not in ("deployer", "agent", "contributor", "launcher"):
            raise HTTPException(
                status_code=400,
                detail="account_type must be 'deployer', 'agent', 'contributor', or 'launcher'",
            )

        if not request.name:
            raise HTTPException(status_code=400, detail="Account name is required")

        existing = account_store.get_by_name(request.name)
        if existing:
            raise HTTPException(status_code=409, detail=f"Account '{request.name}' already exists")

        api_key = generate_api_key_fn("live")
        api_key_hash_val = hash_api_key_fn(api_key)
        api_key_prefix = get_key_prefix_fn(api_key)

        account = Account(
            name=request.name,
            description=request.description,
            account_type=request.account_type,
            api_key_hash=api_key_hash_val,
            api_key_prefix=api_key_prefix,
        )
        account_store.create(account)
        logger.info(f"Account created: {account.name} ({account.account_id})")

        return {
            "account_id": account.account_id,
            "name": account.name,
            "description": account.description,
            "account_type": account.account_type,
            "balance": 0.0,
            "created_at": account.created_at,
            "api_key": api_key,
            "warning": "Save this API key now. It will never be shown again.",
        }

    @app.post("/api/v1/accounts/{account_id}/identity", response_model=AccountResponse)
    async def link_account_identity(
        account_id: str,
        request: AccountLinkIdentityRequest,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Link an account to contributor identity metadata (GitHub login/org)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot edit identity for other accounts")

        account = get_or_404_fn(account_store, account_id, "Account")
        account = account_store.update_identity(
            account_id=account_id,
            github_login=(request.github_login or "").strip() or None,
            github_org=(request.github_org or "").strip() or None,
            linked_at=datetime.now(timezone.utc),
        )
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        return AccountResponse(
            account_id=account.account_id,
            name=account.name,
            description=account.description,
            account_type=account.account_type,
            github_login=account.github_login,
            github_org=account.github_org,
            balance=account_store.get_balance(account.account_id),
            created_at=account.created_at,
        )

    @app.get("/api/v1/accounts", response_model=AccountListResponse)
    async def list_accounts(
        name: str | None = Query(None, description="Filter by name (partial match)"),
        account_type: str | None = Query(None, description="Filter by account type"),
        _admin: AdminSession = Depends(require_admin_session),
    ):
        """List all billing accounts (admin only)."""
        accounts = account_store.list(build_filters_fn(name=name, account_type=account_type))
        responses = [
            AccountResponse(
                account_id=account.account_id,
                name=account.name,
                description=account.description,
                account_type=account.account_type,
                github_login=account.github_login,
                github_org=account.github_org,
                balance=account_store.get_balance(account.account_id),
                created_at=account.created_at,
            )
            for account in accounts
        ]
        return AccountListResponse(accounts=responses, total=len(responses))

    @app.get("/api/v1/accounts/{account_id}", response_model=AccountResponse)
    async def get_account(
        account_id: str,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Get a billing account with its current balance (account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot access other accounts")

        account = get_or_404_fn(account_store, account_id, "Account")
        return AccountResponse(
            account_id=account.account_id,
            name=account.name,
            description=account.description,
            account_type=account.account_type,
            github_login=account.github_login,
            github_org=account.github_org,
            balance=account_store.get_balance(account.account_id),
            created_at=account.created_at,
        )

    @app.post("/api/v1/accounts/{account_id}/api-key/rotate", response_model=ApiKeyRotateResponse)
    async def rotate_account_api_key(
        account_id: str,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Rotate an account API key (account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot rotate API key for other accounts")

        get_or_404_fn(account_store, account_id, "Account")
        new_api_key = generate_api_key_fn("live")
        updated = account_store.update_api_credentials(
            account_id=account_id,
            api_key_hash=hash_api_key_fn(new_api_key),
            api_key_prefix=get_key_prefix_fn(new_api_key),
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Account not found")

        return ApiKeyRotateResponse(
            account_id=account_id,
            api_key=new_api_key,
            rotated_at=datetime.now(timezone.utc),
            warning="Save this API key now. Previous key has been revoked.",
        )

    @app.delete("/api/v1/accounts/{account_id}")
    async def delete_account(
        account_id: str,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Delete a billing account (only if balance is zero, account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot delete other accounts")

        account = get_or_404_fn(account_store, account_id, "Account")
        balance = account_store.get_balance(account_id)
        if balance != 0.0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete account with non-zero balance ({balance:.2f})",
            )
        account_store.delete(account_id)
        logger.info(f"Account deleted: {account.name} ({account_id})")
        return {"status": "deleted", "account_id": account_id}

    @app.post("/api/v1/accounts/{account_id}/deposit", response_model=TransactionResponse)
    async def deposit_to_account(
        account_id: str,
        request: DepositRequest,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Deposit funds into an account (account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot deposit to other accounts")

        txn = create_transaction_fn(
            account_store,
            transaction_store,
            account_id,
            amount=request.amount,
            tx_type="deposit",
            description=request.description or "Deposit",
        )
        logger.info(f"Deposit: {request.amount:.2f} to account {account_id}")
        return TransactionResponse(
            transaction_id=txn.transaction_id,
            account_id=txn.account_id,
            amount=txn.amount,
            balance_after=txn.balance_after,
            tx_type=txn.tx_type,
            description=txn.description,
            reference_id=txn.reference_id,
            created_at=txn.created_at,
        )

    @app.get("/api/v1/accounts/{account_id}/transactions", response_model=TransactionListResponse)
    async def list_account_transactions(
        account_id: str,
        limit: int = Query(50, le=200),
        offset: int = Query(0, ge=0),
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """List transactions for an account (newest first, account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot access other account transactions")

        get_or_404_fn(account_store, account_id, "Account")
        transactions = transaction_store.list_for_account(account_id, limit=limit, offset=offset)
        total = transaction_store.count_for_account(account_id)
        return TransactionListResponse(
            transactions=[
                TransactionResponse(
                    transaction_id=txn.transaction_id,
                    account_id=txn.account_id,
                    amount=txn.amount,
                    balance_after=txn.balance_after,
                    tx_type=txn.tx_type,
                    description=txn.description,
                    reference_id=txn.reference_id,
                    created_at=txn.created_at,
                )
                for txn in transactions
            ],
            total=total,
        )

    @app.get("/api/v1/billing/rates", response_model=RateCardResponse)
    async def get_rate_card():
        """Get the current billing rate card."""
        return RateCardResponse(rates=RATE_CARD)

    @app.post(
        "/api/v1/accounts/{account_id}/capacity/request",
        response_model=CapacityPurchaseResponse,
    )
    async def request_paid_capacity(
        account_id: str,
        request: CapacityPurchaseRequest,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Request warm capacity using billing account authentication."""
        if account_id != authenticated_account_id:
            raise HTTPException(
                status_code=403, detail="Cannot request capacity for other accounts"
            )

        account = get_or_404_fn(account_store, account_id, "Account")
        if account.account_type != "deployer":
            raise HTTPException(
                status_code=403,
                detail="Capacity purchases require a deployer account",
            )

        datacenter = normalize_registration_datacenter_fn(request.datacenter)
        if not datacenter or not datacenter_re.fullmatch(datacenter):
            raise HTTPException(
                status_code=422,
                detail=(
                    "Invalid datacenter. Expected '<cloud>:<zone>' (for example gcp:us-central1-a)"
                ),
            )

        node_size = normalize_registration_node_size_fn(request.node_size)
        if node_size not in {"tiny", "standard", "llm"}:
            raise HTTPException(
                status_code=422,
                detail="Invalid node_size. Expected one of: tiny, standard, llm",
            )

        request_id = f"capacity-{uuid4().hex[:16]}"
        charged_amount_usd = round(
            capacity_unit_price_monthly_usd_fn(node_size)
            * float(request.min_warm_count)
            * float(request.months),
            2,
        )
        billing_enabled = parse_bool_setting_fn(
            get_setting_fn("billing.enabled"),
            fallback=True,
        )
        simulated_payment = parse_bool_setting_fn(
            get_setting_fn("billing.capacity_request_dev_simulation"),
            fallback=True,
        )
        if not billing_enabled:
            simulated_payment = True

        description = (
            f"Warm capacity {datacenter}/{node_size} x{request.min_warm_count} "
            f"for {request.months} month(s)"
        )
        if not billing_enabled:
            txn = create_transaction_fn(
                account_store,
                transaction_store,
                account_id,
                amount=0.0,
                tx_type="charge",
                description=f"[BILLING_DISABLED ${charged_amount_usd:.2f}] {description}",
                reference_id=request_id,
            )
        elif simulated_payment:
            txn = create_transaction_fn(
                account_store,
                transaction_store,
                account_id,
                amount=0.0,
                tx_type="charge",
                description=f"[SIMULATED ${charged_amount_usd:.2f}] {description}",
                reference_id=request_id,
            )
        else:
            txn = create_transaction_fn(
                account_store,
                transaction_store,
                account_id,
                amount=-charged_amount_usd,
                tx_type="charge",
                description=description,
                reference_id=request_id,
            )

        reason = (request.reason or "").strip() or "capacity-purchase"
        reconcile_reason = f"{reason}:{request_id}"
        target = capacity_pool_target_store.upsert(
            datacenter=datacenter,
            node_size=node_size,
            min_warm_count=request.min_warm_count,
            enabled=True,
            require_verified=True,
            require_healthy=True,
            require_hostname=True,
            dispatch=True,
            reason=reconcile_reason,
        )

        capacity_result = await reconcile_agent_capacity_fn(
            AgentCapacityReconcileRequest(
                targets=[
                    AgentCapacityTarget(
                        datacenter=datacenter,
                        node_size=node_size,
                        min_count=request.min_warm_count,
                    )
                ],
                require_verified=True,
                require_healthy=True,
                require_hostname=True,
                allowed_statuses=["undeployed", "deployed", "deploying"],
                dispatch=True,
                reason=reconcile_reason,
                account_id=account_id,
            ),
            _admin=True,
        )

        target_view = capacity_pool_target_view_fn(
            datacenter=(target.datacenter or "").strip().lower(),
            node_size=(target.node_size or "").strip().lower(),
            min_warm_count=target.min_warm_count,
            enabled=target.enabled,
            require_verified=target.require_verified,
            require_healthy=target.require_healthy,
            require_hostname=target.require_hostname,
            dispatch=target.dispatch,
            reason=target.reason,
            agents=agent_store.list(),
        )

        logger.info(
            "Capacity purchase requested: account=%s datacenter=%s node_size=%s min_warm=%d "
            "months=%d simulated=%s charge=%.2f",
            account_id,
            datacenter,
            node_size,
            request.min_warm_count,
            request.months,
            simulated_payment,
            charged_amount_usd,
        )

        return CapacityPurchaseResponse(
            request_id=request_id,
            account_id=account_id,
            datacenter=datacenter,
            node_size=node_size,
            min_warm_count=request.min_warm_count,
            months=request.months,
            simulated_payment=simulated_payment,
            charged_amount_usd=charged_amount_usd,
            transaction_id=txn.transaction_id,
            balance_after=txn.balance_after,
            target=target_view,
            capacity=capacity_result,
        )

    @app.get(
        "/api/v1/accounts/{account_id}/capacity/orders",
        response_model=CapacityLaunchOrderListResponse,
    )
    async def list_account_capacity_launch_orders(
        account_id: str,
        status: str = Query("", description="Filter by order status"),
        datacenter: str = Query("", description="Optional datacenter filter"),
        node_size: str = Query("", description="Optional node_size filter"),
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """List this account's capacity launch orders."""
        if account_id != authenticated_account_id:
            raise HTTPException(status_code=403, detail="Cannot access other account orders")

        normalized_status = (status or "").strip().lower()
        if normalized_status and normalized_status not in {
            "open",
            "claimed",
            "provisioning",
            "fulfilled",
            "failed",
        }:
            raise HTTPException(status_code=422, detail="Invalid launch order status filter")

        rows = capacity_launch_order_store.list(
            normalized_status or None,
            datacenter=datacenter,
            node_size=node_size,
            account_id=account_id,
        )
        views = [capacity_launch_order_view_fn(row) for row in rows]
        return CapacityLaunchOrderListResponse(orders=views, total=len(views))

    @app.post("/api/v1/accounts/{account_id}/payment-intent")
    async def create_payment_intent(
        account_id: str,
        request: CreatePaymentIntentRequest,
        authenticated_account_id: str = Depends(verify_account_api_key),
    ):
        """Create a Stripe payment intent for depositing funds (account owner only)."""
        if account_id != authenticated_account_id:
            raise HTTPException(
                status_code=403, detail="Cannot create payment intent for other accounts"
            )

        from .billing import _ensure_stripe, _stripe_mod

        if not _ensure_stripe():
            raise HTTPException(
                status_code=503,
                detail=(
                    "Stripe integration not configured. Set STRIPE_SECRET_KEY environment variable."
                ),
            )

        get_or_404_fn(account_store, account_id, "Account")

        try:
            intent = _stripe_mod.PaymentIntent.create(
                amount=int(request.amount * 100),
                currency="usd",
                metadata={"account_id": account_id},
            )
            logger.info(f"Created payment intent for account {account_id}: ${request.amount:.2f}")
            return {
                "client_secret": intent.client_secret,
                "amount": request.amount,
                "payment_intent_id": intent.id,
            }
        except Exception as exc:
            logger.error(f"Error creating Stripe payment intent: {exc}")
            raise HTTPException(
                status_code=500, detail=f"Failed to create payment intent: {str(exc)}"
            ) from exc

    @app.post("/api/v1/webhooks/stripe")
    async def stripe_webhook(request: Request):
        """Stripe webhook endpoint for payment confirmations."""
        from .billing import _ensure_stripe, _stripe_mod, _webhook_secret

        if not _ensure_stripe():
            raise HTTPException(status_code=503, detail="Stripe integration not configured")

        payload = await request.body()
        sig_header = request.headers.get("stripe-signature")
        if not sig_header:
            raise HTTPException(status_code=400, detail="Missing stripe-signature header")

        try:
            event = _stripe_mod.Webhook.construct_event(payload, sig_header, _webhook_secret())
        except ValueError as exc:
            logger.error("Invalid Stripe webhook payload")
            raise HTTPException(status_code=400, detail="Invalid payload") from exc
        except _stripe_mod.error.SignatureVerificationError as exc:
            logger.error("Invalid Stripe webhook signature")
            raise HTTPException(status_code=400, detail="Invalid signature") from exc

        if event["type"] == "payment_intent.succeeded":
            payment_intent = event["data"]["object"]
            account_id = payment_intent["metadata"].get("account_id")
            amount = payment_intent["amount"] / 100.0

            if account_id:
                try:
                    create_transaction_fn(
                        account_store,
                        transaction_store,
                        account_id,
                        amount=amount,
                        tx_type="deposit",
                        description="Stripe payment",
                        reference_id=payment_intent["id"],
                    )
                    logger.info(
                        "Processed Stripe payment: $%.2f deposited to account %s",
                        amount,
                        account_id,
                    )
                except Exception as exc:
                    logger.error(f"Error processing Stripe payment: {exc}")
            else:
                logger.warning(
                    "Stripe payment intent %s has no account_id metadata",
                    payment_intent["id"],
                )

        return {"status": "ok"}
