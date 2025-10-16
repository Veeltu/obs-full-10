locals {
  namespace = "network"
  # Load Shared/Common Variables that can be used in all terraform configurations. 
  # Can be override via Terragrunt.hcl
  common_vars      = read_terragrunt_config("../common.hcl")
  impersonate_vars = read_terragrunt_config("../impersonate.hcl")
  working_dir_fullpath = get_terragrunt_dir()
  working_dir_parts = split("/", local.working_dir_fullpath)

  # secret_suffix     = "network-otel-collector-dev"
  secret_suffix = "${local.namespace}-${element(local.working_dir_parts, length(local.working_dir_parts)-1)}-${element(local.working_dir_parts, length(local.working_dir_parts)-2)}"

  # secret_suffix     = "otel-collector-dev"
  # secret_suffix = "${element(local.working_dir_parts, length(local.working_dir_parts)-1)}-${element(local.working_dir_parts, length(local.working_dir_parts)-2)}"

  config_path = "~/.kube/config"
  config_context = "pndrs-observability"
  # config_context = "gke_smanke-dev-test-5mkmp_europe-west3_autopilot-cluster-1"
}

generate "provider" {
  path = "main.provider.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<-EOF

provider "kubernetes" {
  config_path = "${local.config_path}"
  config_context = "${local.config_context}"
}

provider "helm" {
  kubernetes {
  config_path = "${local.config_path}"
  config_context = "${local.config_context}"
  }  
}

terraform {
  required_version = ">=1.4.6"

  required_providers {
    kubectl = {
      source  = "registry.terraform.io/gavinbunney/kubectl"
      version = "= 1.19.0"
    }
    helm = {
      source = "hashicorp/helm"
      version = "= 2.16.1"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "= 2.33.0"
    }
    kustomization = {
      source  = "kbst/kustomization"
      version = "= 0.9.6"
    }
    grafana = {
      source = "grafana/grafana"
      version = "= 3.19.0"
    }
  }
}
EOF
}

# remote_state {
#   backend = "kubernetes"
#   config = {
#     secret_suffix = local.secret_suffix
#     config_path = local.config_path
#     config_context = local.config_context
#   }
#   generate = {
#     path = "backend.tf"
#     if_exists = "overwrite_terragrunt"
#   }
# }

# Merge locals from common.hcl & make it usable in terragrunt.hcl file.
# These Variables can be overwritten in the terragrunt.hcl file.
# Important: The Input order has to match the inputs in the terragrunt.hcl file.
inputs = merge(
  local.common_vars.locals,
)
