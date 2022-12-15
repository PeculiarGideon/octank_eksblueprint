locals {
  name             = try(var.helm_config.name, "grafana")
  namespace_name   = try(var.helm_config.namespace, "grafana")
  create_namespace = try(var.helm_config.create_namespace, true) && local.namespace_name != "kube-system"

  # `namespace_name` is just the string representation of the namespace name
  # `namespace` is the name of the resultant namespace to use - created or not
  namespace = local.create_namespace ? kubernetes_namespace_v1.prometheus[0].metadata[0].name : local.namespace_name

  workspace_url          = var.amazon_prometheus_workspace_endpoint != null ? "${var.amazon_prometheus_workspace_endpoint}api/v1/remote_write" : ""
  ingest_service_account = "amp-ingest"
  ingest_iam_role_arn    = var.enable_amazon_prometheus ? module.irsa_amp_ingest[0].irsa_iam_role_arn : ""

  amp_gitops_config = var.enable_amazon_prometheus ? {
    roleArn            = local.ingest_iam_role_arn
    ampWorkspaceUrl    = local.workspace_url
    serviceAccountName = local.ingest_service_account
  } : {}
}


module "managed_grafana" {
  source = "terraform-aws-modules/managed-service-grafana/aws"

  # Workspace
  name                      = locals.name
  description               = "AWS Managed Grafana service example workspace"
  account_access_type       = "CURRENT_ACCOUNT"
  authentication_providers  = ["AWS_SSO"]
  permission_type           = "SERVICE_MANAGED"
  data_sources              = ["CLOUDWATCH", "PROMETHEUS", "XRAY"]
  notification_destinations = ["SNS"]

  # Workspace API keys
  workspace_api_keys = {
    viewer = {
      key_name        = "viewer"
      key_role        = "VIEWER"
      seconds_to_live = 3600
    }
    editor = {
      key_name        = "editor"
      key_role        = "EDITOR"
      seconds_to_live = 3600
    }
    admin = {
      key_name        = "admin"
      key_role        = "ADMIN"
      seconds_to_live = 3600
    }
  }

  # Workspace SAML configuration
  saml_admin_role_values  = ["admin"]
  saml_editor_role_values = ["editor"]
  saml_email_assertion    = "mail"
  saml_groups_assertion   = "groups"
  saml_login_assertion    = "mail"
  saml_name_assertion     = "displayName"
  saml_org_assertion      = "org"
  saml_role_assertion     = "role"
  saml_idp_metadata_url   = "https://my_idp_metadata.url"

  # Role associations
  role_associations = {
    "ADMIN" = {
      "group_ids" = ["5448b458-6061-7037-7fa1-b0f69b730fd4"]
    }
    "EDITOR" = {
      "user_ids" = ["34c894d8-a011-7079-b701-70ace60825b2"]
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}