terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>4.0"
    }
  }

  required_version = "~> 1.14.3"

  backend "azurerm" {
    resource_group_name  = "s194d00-SSPHP-GitHub-Webhooks"
    storage_account_name = "tfstateee5pt"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }
}

locals {
  resource_group = "s194d00-SSPHP-GitHub-Webhooks"
  tags = {
    "Product"          = "Protective Monitoring - Splunk SaaS"
    "Environment"      = "Dev"
    "Service Offering" = "Protective Monitoring - Splunk SaaS"

  }
  sku_name_rust      = "Y1"
  // sku_name_rust  = "EP1"
  key_vault_name = "SSPHP-GitHub-Webhooks"
  key_vault_object_ids = [
    "393279ef-dc89-4bff-8186-4d283ee7b280", // Me
    "b7ecf1ae-c14f-4be8-a8d1-db7b5157d5d9", // Github deployer
    "00b97bd8-b1cc-4aa5-8e9f-da02227d1dae", // IP
  ] 
}

provider "azurerm" {
  features {}
}

module "github_webhooks" {
  source         = "../github_webhooks"
  resource_group = local.resource_group
  #  sku_name_python      = local.sku_name_python
  sku_name_rust        = local.sku_name_rust
  key_vault_name       = local.key_vault_name
  key_vault_object_ids = local.key_vault_object_ids
  tags                 = local.tags
  # vnet = {
  #   name                = "s194d01-core-vn-01",
  #   subnet_name         = "s194d01-core-sn-01",
  #   resource_group_name = "s194d01-core"
  # }
}
