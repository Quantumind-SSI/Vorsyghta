terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  default = "eastus2"
}

resource "azurerm_resource_group" "vorsyghta" {
  name     = "vorsyghta-rg"
  location = var.location
}

resource "azurerm_key_vault" "vorsyghta" {
  name                        = "vorsyghta-kv"
  location                    = azurerm_resource_group.vorsyghta.location
  resource_group_name         = azurerm_resource_group.vorsyghta.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 90
  enable_rbac_authorization   = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_cognitive_account" "openai" {
  name                = "vorsyghta-openai"
  location            = azurerm_resource_group.vorsyghta.location
  resource_group_name = azurerm_resource_group.vorsyghta.name
  kind                = "OpenAI"
  sku_name            = "S0"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cognitive_deployment" "gpt4o" {
  name                 = "gpt-4o"
  cognitive_account_id = azurerm_cognitive_account.openai.id
  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }
  scale {
    type = "Standard"
  }
}

resource "azurerm_container_app_environment" "env" {
  name                       = "vorsyghta-env"
  location                   = azurerm_resource_group.vorsyghta.location
  resource_group_name        = azurerm_resource_group.vorsyghta.name
  infrastructure_subnet_id   = null
}

resource "azurerm_container_app" "api" {
  name                         = "vorsyghta-api"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.vorsyghta.name
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  template {
    container {
      name   = "api"
      image  = "vorsyghtaacr1782424350.azurecr.io/vorsyghta-attack:latest"
      cpu    = 1.0
      memory = "2Gi"
      env {
        name  = "AZURE_KEY_VAULT_URL"
        value = "https://vorsyghta-kv.vault.azure.net/"
      }
      env {
        name  = "AZURE_OPENAI_ENDPOINT"
        value = "https://vorsyghta-openai.openai.azure.com/"
      }
      env {
        name  = "AZURE_RESOURCE_GROUP"
        value = "vorsyghta-rg"
      }
    }
  }
}

output "key_vault_url" {
  value = azurerm_key_vault.vorsyghta.vault_uri
}

output "openai_endpoint" {
  value = azurerm_cognitive_account.openai.endpoint
}
