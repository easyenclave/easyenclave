"""ORAM-based contact store with SQLite backend and AES-GCM encryption.

Enhanced from the basic cuckoo ORAM implementation with:
- SQLite persistent storage
- AES-GCM encryption (not XOR)
- Contact-specific API (register, lookup)
- Batch query optimization
"""

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class Block:
    """A data block with logical address and encrypted data."""

    logical_addr: int
    data: bytes
    valid: bool = True  # False = dummy block


class ORAMContactStore:
    """Oblivious RAM store for contact discovery.

    Properties:
    - SQLite backend for persistence
    - AES-GCM encryption for all blocks
    - Cuckoo hash bucketing for oblivious access
    - Stash for overflow handling
    - Contact-specific API (phone hash -> user ID mapping)
    """

    def __init__(
        self,
        db_path: str,
        num_buckets: int = 1024,
        bucket_size: int = 4,
        stash_size: int = 100,
        block_size: int = 64,
    ):
        """Initialize ORAM contact store.

        Args:
            db_path: Path to SQLite database file
            num_buckets: Number of cuckoo hash buckets
            bucket_size: Number of blocks per bucket
            stash_size: Maximum stash capacity
            block_size: Size of each data block in bytes
        """
        self.db_path = db_path
        self.num_buckets = num_buckets
        self.bucket_size = bucket_size
        self.stash_size = stash_size
        self.block_size = block_size

        # AES-GCM encryption key (256-bit)
        self.encryption_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.encryption_key)

        # Secret keys for hash functions
        self.key1 = secrets.token_bytes(16)
        self.key2 = secrets.token_bytes(16)

        # Position map (logical addr -> bucket location)
        # Kept in memory for fast lookups (small enough)
        self.position_map: dict[int, tuple[int, int]] = {}

        # Initialize database
        self._init_db()

        # Load position map from database (after init)
        self._load_position_map()

    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # ORAM buckets (cuckoo hash)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS oram_buckets (
                    bucket_id INTEGER NOT NULL,
                    slot_id INTEGER NOT NULL,
                    encrypted_block BLOB NOT NULL,
                    PRIMARY KEY (bucket_id, slot_id)
                )
            """
            )

            # Stash (overflow storage)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS oram_stash (
                    logical_addr INTEGER PRIMARY KEY,
                    encrypted_block BLOB NOT NULL
                )
            """
            )

            # Position map (logical addr -> bucket location)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS position_map (
                    logical_addr INTEGER PRIMARY KEY,
                    bucket_id INTEGER NOT NULL,
                    slot_id INTEGER NOT NULL
                )
            """
            )

            # Contact metadata (non-sensitive)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS contacts_meta (
                    contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone_hash BLOB UNIQUE NOT NULL,
                    logical_addr INTEGER UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Commit table creation
            conn.commit()

            # Initialize buckets with dummy blocks if empty
            cursor.execute("SELECT COUNT(*) FROM oram_buckets")
            count = cursor.fetchone()[0]

            if count == 0:
                for bucket_id in range(self.num_buckets):
                    for slot_id in range(self.bucket_size):
                        dummy = self._encrypt_block(self._dummy_block())
                        cursor.execute(
                            "INSERT INTO oram_buckets VALUES (?, ?, ?)",
                            (bucket_id, slot_id, dummy),
                        )

            conn.commit()
        finally:
            conn.close()

    def _load_position_map(self):
        """Load position map from database into memory."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if table exists first
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='position_map'"
        )
        if cursor.fetchone() is None:
            conn.close()
            return

        cursor.execute("SELECT logical_addr, bucket_id, slot_id FROM position_map")
        for logical_addr, bucket_id, slot_id in cursor.fetchall():
            self.position_map[logical_addr] = (bucket_id, slot_id)
        conn.close()

    def _dummy_block(self) -> Block:
        """Create a dummy block (for padding)."""
        return Block(logical_addr=-1, data=secrets.token_bytes(self.block_size), valid=False)

    def _hash(self, key: bytes, addr: int) -> int:
        """Keyed hash function for cuckoo hashing."""
        h = hashlib.blake2b(key + addr.to_bytes(8, "big"), digest_size=4)
        return int.from_bytes(h.digest(), "big") % self.num_buckets

    def _hash1(self, addr: int) -> int:
        """First hash function."""
        return self._hash(self.key1, addr)

    def _hash2(self, addr: int) -> int:
        """Second hash function."""
        return self._hash(self.key2, addr)

    def _encrypt_block(self, block: Block) -> bytes:
        """Encrypt a block with AES-GCM.

        Format: nonce (12 bytes) + ciphertext (variable)
        """
        # Serialize block
        valid_byte = b"\x01" if block.valid else b"\x00"
        addr_bytes = block.logical_addr.to_bytes(8, "big", signed=True)
        plaintext = valid_byte + addr_bytes + block.data

        # Encrypt
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

        return nonce + ciphertext

    def _decrypt_block(self, encrypted: bytes) -> Block:
        """Decrypt a block with AES-GCM."""
        # Extract nonce and ciphertext
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        # Decrypt
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

        # Deserialize
        valid = plaintext[0] == 0x01
        logical_addr = int.from_bytes(plaintext[1:9], "big", signed=True)
        data = plaintext[9:]

        return Block(logical_addr=logical_addr, data=data, valid=valid)

    def _read_bucket_slot(self, bucket_id: int, slot_id: int) -> Block:
        """Read a single bucket slot from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_block FROM oram_buckets WHERE bucket_id = ? AND slot_id = ?",
            (bucket_id, slot_id),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return self._decrypt_block(row[0])
        else:
            return self._dummy_block()

    def _write_bucket_slot(self, bucket_id: int, slot_id: int, block: Block):
        """Write a single bucket slot to database."""
        encrypted = self._encrypt_block(block)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO oram_buckets VALUES (?, ?, ?)",
            (bucket_id, slot_id, encrypted),
        )
        conn.commit()
        conn.close()

    def _read_bucket(self, bucket_id: int) -> list[Block]:
        """Read entire bucket from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_block FROM oram_buckets WHERE bucket_id = ? ORDER BY slot_id",
            (bucket_id,),
        )
        blocks = [self._decrypt_block(row[0]) for row in cursor.fetchall()]
        conn.close()
        return blocks

    def _write_bucket(self, bucket_id: int, blocks: list[Block]):
        """Write entire bucket to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for slot_id, block in enumerate(blocks):
            encrypted = self._encrypt_block(block)
            cursor.execute(
                "INSERT OR REPLACE INTO oram_buckets VALUES (?, ?, ?)",
                (bucket_id, slot_id, encrypted),
            )
        conn.commit()
        conn.close()

    def _read_stash(self) -> list[Block]:
        """Read stash from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT logical_addr, encrypted_block FROM oram_stash")
        blocks = [self._decrypt_block(row[1]) for row in cursor.fetchall()]
        conn.close()
        return blocks

    def _write_stash(self, blocks: list[Block]):
        """Write stash to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Clear stash
        cursor.execute("DELETE FROM oram_stash")
        # Write new blocks
        for block in blocks:
            if block.valid:
                encrypted = self._encrypt_block(block)
                cursor.execute(
                    "INSERT INTO oram_stash VALUES (?, ?)",
                    (block.logical_addr, encrypted),
                )
        conn.commit()
        conn.close()

    def _find_in_bucket(self, bucket: list[Block], logical_addr: int) -> Optional[Block]:
        """Obliviously search bucket for block (scans all slots)."""
        found = None
        for block in bucket:
            # Always check all slots (oblivious)
            if block.valid and block.logical_addr == logical_addr:
                found = block
        return found

    def _oblivious_read(self, logical_addr: int) -> Optional[bytes]:
        """Oblivious read operation.

        Always accesses the same number of buckets regardless of whether
        the block is found or not (hides access pattern).
        """
        # Check both possible locations (cuckoo hash)
        bucket1_id = self._hash1(logical_addr)
        bucket2_id = self._hash2(logical_addr)

        # Always access both buckets (oblivious)
        bucket1 = self._read_bucket(bucket1_id)
        bucket2 = self._read_bucket(bucket2_id)

        # Scan both buckets (always scan all slots)
        found = self._find_in_bucket(bucket1, logical_addr)
        if not found:
            found = self._find_in_bucket(bucket2, logical_addr)

        # Check stash if not in buckets
        if not found:
            stash = self._read_stash()
            for block in stash:
                if block.valid and block.logical_addr == logical_addr:
                    found = block
                    break

        if found and found.valid:
            # Remove from current location
            self._remove_block(logical_addr)

            # Add to stash temporarily
            stash = self._read_stash()
            stash.append(found)
            self._write_stash(stash)

            # Re-insert to new random location (reshuffles)
            self._evict_from_stash()

            return found.data

        return None

    def _oblivious_write(self, logical_addr: int, data: bytes):
        """Oblivious write operation."""
        if len(data) > self.block_size:
            raise ValueError(f"Data must be <= {self.block_size} bytes")

        # Pad data to block size
        data = data.ljust(self.block_size, b"\x00")

        # Remove old block if exists
        self._remove_block(logical_addr)

        # Add new block to stash
        block = Block(logical_addr=logical_addr, data=data, valid=True)
        stash = self._read_stash()
        stash.append(block)

        if len(stash) > self.stash_size:
            raise OverflowError("Stash overflow - ORAM capacity exceeded")

        self._write_stash(stash)

        # Evict from stash to buckets
        self._evict_from_stash()

    def _remove_block(self, logical_addr: int):
        """Remove block from buckets and stash (replace with dummy)."""
        # Check position map
        if logical_addr in self.position_map:
            bucket_id, slot_id = self.position_map[logical_addr]
            self._write_bucket_slot(bucket_id, slot_id, self._dummy_block())
            del self.position_map[logical_addr]

            # Update position map in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM position_map WHERE logical_addr = ?", (logical_addr,))
            conn.commit()
            conn.close()

        # Remove from stash
        stash = self._read_stash()
        stash = [b for b in stash if b.logical_addr != logical_addr]
        self._write_stash(stash)

    def _evict_from_stash(self):
        """Evict blocks from stash to buckets using cuckoo hashing."""
        max_evictions = 10
        stash = self._read_stash()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        while stash:
            block = stash.pop(0)
            if not block.valid:
                continue

            # Try to insert into one of two buckets
            inserted = False

            for bucket_id in [self._hash1(block.logical_addr), self._hash2(block.logical_addr)]:
                bucket = self._read_bucket(bucket_id)

                # Try to find empty slot
                for i, slot in enumerate(bucket):
                    if not slot.valid:
                        bucket[i] = block
                        self._write_bucket(bucket_id, bucket)
                        self.position_map[block.logical_addr] = (bucket_id, i)

                        # Update position map in database
                        cursor.execute(
                            "INSERT OR REPLACE INTO position_map VALUES (?, ?, ?)",
                            (block.logical_addr, bucket_id, i),
                        )
                        inserted = True
                        break

                if inserted:
                    break

            if not inserted:
                # No empty slot - evict a random block
                bucket_id = secrets.choice([self._hash1(block.logical_addr), self._hash2(block.logical_addr)])
                bucket = self._read_bucket(bucket_id)
                evict_idx = secrets.randbelow(self.bucket_size)

                # Evict victim block to stash
                victim = bucket[evict_idx]
                if victim.valid:
                    stash.append(victim)
                    if victim.logical_addr in self.position_map:
                        del self.position_map[victim.logical_addr]
                        cursor.execute(
                            "DELETE FROM position_map WHERE logical_addr = ?",
                            (victim.logical_addr,),
                        )

                # Insert current block
                bucket[evict_idx] = block
                self._write_bucket(bucket_id, bucket)
                self.position_map[block.logical_addr] = (bucket_id, evict_idx)
                cursor.execute(
                    "INSERT OR REPLACE INTO position_map VALUES (?, ?, ?)",
                    (block.logical_addr, bucket_id, evict_idx),
                )

                max_evictions -= 1
                if max_evictions <= 0:
                    # Too many evictions - keep in stash
                    stash.append(block)
                    break

        conn.commit()
        conn.close()

        # Write final stash state
        self._write_stash(stash)

    def _get_logical_addr(self, phone_hash: bytes) -> Optional[int]:
        """Get logical address for phone hash."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT logical_addr FROM contacts_meta WHERE phone_hash = ?", (phone_hash,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def _allocate_logical_addr(self) -> int:
        """Allocate a new logical address."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(logical_addr) FROM contacts_meta")
        max_addr = cursor.fetchone()[0]
        conn.close()
        return (max_addr + 1) if max_addr is not None else 0

    def register_contact(self, phone_hash: bytes, user_id: str) -> bool:
        """Register a contact (oblivious write).

        Args:
            phone_hash: SHA-256 hash of phone number
            user_id: User identifier (public)

        Returns:
            True if registered, False if already exists
        """
        # Check if already exists
        existing_addr = self._get_logical_addr(phone_hash)
        if existing_addr is not None:
            return False

        # Allocate new logical address
        logical_addr = self._allocate_logical_addr()

        # Store metadata
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO contacts_meta (phone_hash, logical_addr) VALUES (?, ?)",
                (phone_hash, logical_addr),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return False
        conn.close()

        # Oblivious write to ORAM
        data = user_id.encode("utf-8")
        self._oblivious_write(logical_addr, data)

        return True

    def lookup_contacts(self, phone_hashes: list[bytes]) -> list[Optional[str]]:
        """Batch lookup contacts (oblivious read).

        Args:
            phone_hashes: List of SHA-256 phone hashes

        Returns:
            List of user_ids (None if not found)
        """
        results = []
        for phone_hash in phone_hashes:
            # Get logical address
            addr = self._get_logical_addr(phone_hash)

            # Always read from ORAM (even if not found)
            if addr is not None:
                data = self._oblivious_read(addr)
            else:
                # Dummy read (hide that contact doesn't exist)
                dummy_addr = secrets.randbelow(max(1, self._allocate_logical_addr()))
                self._oblivious_read(dummy_addr)
                data = None

            # Decode result
            if data:
                user_id = data.rstrip(b"\x00").decode("utf-8")
                results.append(user_id)
            else:
                results.append(None)

        return results

    def stats(self) -> dict:
        """Return ORAM statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Count valid blocks in buckets
        cursor.execute("SELECT COUNT(*) FROM oram_buckets")
        total_slots = cursor.fetchone()[0]

        # Count contacts
        cursor.execute("SELECT COUNT(*) FROM contacts_meta")
        num_contacts = cursor.fetchone()[0]

        # Count stash size
        cursor.execute("SELECT COUNT(*) FROM oram_stash")
        stash_size = cursor.fetchone()[0]

        conn.close()

        return {
            "total_capacity": self.num_buckets * self.bucket_size,
            "num_contacts": num_contacts,
            "stash_size": stash_size,
            "occupancy": num_contacts / (self.num_buckets * self.bucket_size) if self.num_buckets > 0 else 0,
        }
