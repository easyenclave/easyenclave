packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.3"
    }
  }
}

variable "base_image_url" {
  type = string
}

variable "base_image_checksum" {
  type    = string
  default = "none"
}

variable "output_directory" {
  type = string
}

variable "vm_name" {
  type = string
}

variable "accelerator" {
  type    = string
  default = "kvm"
}

variable "disk_size" {
  type = string
}

variable "cpus" {
  type = number
}

variable "memory_mb" {
  type = number
}

variable "ssh_username" {
  type = string
}

variable "ssh_password" {
  type      = string
  sensitive = true
}

variable "ssh_timeout" {
  type    = string
  default = "20m"
}

variable "cloud_init_seed_path" {
  type = string
}

variable "agent_binary_path" {
  type = string
}

source "qemu" "baremetal" {
  accelerator      = var.accelerator
  headless         = true
  output_directory = var.output_directory
  vm_name          = var.vm_name
  format           = "qcow2"
  disk_size        = var.disk_size
  disk_image       = true
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_interface   = "virtio"
  net_device       = "virtio-net"
  cpus             = var.cpus
  memory           = var.memory_mb
  boot_wait        = "5s"
  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = var.ssh_timeout
  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"

  qemuargs = [
    ["-drive", "file=${var.cloud_init_seed_path},if=virtio,format=raw,media=cdrom,readonly=on"]
  ]
}

build {
  name    = "easyenclave-baremetal-agent"
  sources = ["source.qemu.baremetal"]

  provisioner "file" {
    source      = var.agent_binary_path
    destination = "/tmp/ee-agent"
  }

  provisioner "shell" {
    script          = "${path.root}/provision-agent-image.sh"
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash -euxo pipefail {{ .Path }}"
  }
}
