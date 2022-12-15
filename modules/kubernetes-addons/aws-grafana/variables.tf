variable "helm_config" {
  description = "Helm Config for Prometheus"
  type        = any
  default     = {}
}

variable "enable_amazon_prometheus" {
  description = "Enable AWS Managed Prometheus service"
  type        = bool
  default     = false
}

variable "amazon_prometheus_workspace_endpoint" {
  description = "Amazon Managed Prometheus Workspace Endpoint"
  type        = string
  default     = null
}

variable "manage_via_gitops" {
  description = "Determines if the add-on should be managed via GitOps."
  type        = bool
  default     = false
}

variable "addon_context" {
  description = "Input configuration for the addon"
  type = object({
    aws_caller_identity_account_id = string
    aws_caller_identity_arn        = string
    aws_eks_cluster_endpoint       = string
    aws_partition_id               = string
    aws_region_name                = string
    eks_cluster_id                 = string
    eks_oidc_issuer_url            = string
    eks_oidc_provider_arn          = string
    tags                           = map(string)
    irsa_iam_role_path             = string
    irsa_iam_permissions_boundary  = string
  })
}

/*

variable "addon_context" {
  description = "Input configuration for the addon"
  type = object ({aws_caller_identity_account_id = "716249003358"
    aws_caller_identity_arn        = "arn:aws:sts::716249003358:assumed-role/Admin/vikdhir-Isengard"
    aws_eks_cluster_endpoint       = "https://18808E22D4E55F604481B470C10BA2AF.yl4.us-east-1.eks.amazonaws.com"
    aws_partition_id               = "aws"
    aws_region_name                = "us-east-1"
    eks_cluster_id                 = "octank-v5"
    eks_oidc_issuer_url            = "https://oidc.eks.us-east-1.amazonaws.com/id/18808E22D4E55F604481B470C10BA2AF"
    eks_oidc_provider_arn          = "arn:aws:iam::716249003358:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/18808E22D4E55F604481B470C10BA2AF"
    tags                           = local.tags
    irsa_iam_role_path             = ""
    irsa_iam_permissions_boundary  = ""
    })
}
*/
