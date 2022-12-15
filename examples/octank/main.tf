

provider "aws" {
  region = local.region
}

provider "bcrypt" {
}

provider "kubernetes" {
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks_blueprints.eks_cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}


data "aws_eks_cluster_auth" "this" {
  name = module.eks_blueprints.eks_cluster_id
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

locals {
  
  region = "us-east-2"

  name   = join("",[basename(path.cwd),"-",local.region])  # add reegion to cluster name to avoid IAM role name conflicts 

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 2) #number of AZs

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/terraform-aws-eks-blueprints"
  }
}

#---------------------------------------------------------------
# Create Namespaces
#---------------------------------------------------------------

resource "kubernetes_namespace" "general-insurance" {
  metadata {
    name = "general-insurance"
  }
}


resource "kubernetes_namespace" "private-client-group" {
  metadata {
    name = "private-client-group"
  }
}

resource "kubernetes_namespace" "ecsdemo-frontend" {
  metadata {
    name = "ecsdemo-frontend"
  }
}

resource "kubernetes_namespace" "ecsdemo-nodejs" {
  metadata {
    name = "ecsdemo-nodejs"
  }
}

resource "kubernetes_namespace" "ecsdemo-crystal" {
  metadata {
    name = "ecsdemo-crystal"
  }
}

#---------------------------------------------------------------
# EKS Blueprints
#---------------------------------------------------------------

module "eks_blueprints" {
  source = "../.."

  cluster_name    = local.name
  cluster_version = "1.23"

  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnets

  # https://github.com/aws-ia/terraform-aws-eks-blueprints/issues/485
  # https://github.com/aws-ia/terraform-aws-eks-blueprints/issues/494
  cluster_kms_key_additional_admin_arns = [data.aws_caller_identity.current.arn]

  #----------------------------------------------------------------------------------------------------------#
  # Security groups used in this module created by the upstream modules terraform-aws-eks (https://github.com/terraform-aws-modules/terraform-aws-eks).
  #   Upstream module implemented Security groups based on the best practices doc https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html.
  #   So, by default the security groups are restrictive. Users needs to enable rules for specific ports required for App requirement or Add-ons
  #   See the notes below for each rule used in these examples
  #----------------------------------------------------------------------------------------------------------#
  node_security_group_additional_rules = {
    # Extend node-to-node security group rules. Recommended and required for the Add-ons
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    # Recommended outbound traffic for Node groups
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    # Allows Control Plane Nodes to talk to Worker nodes on all ports. Added this to simplify the example and further avoid issues with Add-ons communication with Control plane.
    # This can be restricted further to specific port based on the requirement for each Add-on e.g., metrics-server 4443, spark-operator 8080, karpenter 8443 etc.
    # Change this according to your security requirements if needed
    ingress_cluster_to_node_all_traffic = {
      description                   = "Cluster API to Nodegroup all traffic"
      protocol                      = "-1"
      from_port                     = 0
      to_port                       = 0
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  
  fargate_profiles = {
    # Providing compute for default namespace
    default = {
      fargate_profile_name = "default"
      fargate_profile_namespaces = [
        {
          namespace = "default"
      }]
      subnet_ids = module.vpc.private_subnets
    }
    # Providing compute for kube-system namespace where core addons reside
    kube_system = {
      fargate_profile_name = "kube-system"
      fargate_profile_namespaces = [
        {
          namespace = "kube-system"
      }]
      subnet_ids = module.vpc.private_subnets
    }

     
    # AIG General Insurance 
    general_insurance = {
      fargate_profile_name = "general-insurance"
      fargate_profile_namespaces = [
        {
          namespace = "general-insurance"
      }] 
      subnet_ids = module.vpc.private_subnets
    }

   /* # Sample application
    app = {
      fargate_profile_name = "app-wildcard"
      fargate_profile_namespaces = [
        {
          namespace = "app-*"
      }]
      subnet_ids = module.vpc.private_subnets
    }
   
    
    # AIG Private Client Group 
    private_client_group = {
      fargate_profile_name = "private-client-group"
      fargate_profile_namespaces = [
        {
          namespace = "private-client-group"
      }]
      subnet_ids = module.vpc.private_subnets
    }
    */

  }
  





   managed_node_groups = {
    mg_5 = {
      node_group_name      = "managed-ondemand"
      instance_types       = ["m5.large"]
      subnet_ids           = module.vpc.private_subnets
      force_update_version = true
    }
  }
  tags = local.tags
}


#---------------------------------------------------------------
# EKS Add Ons
#---------------------------------------------------------------

module "eks_blueprints_kubernetes_addons" {
  source = "../../modules/kubernetes-addons"

  eks_cluster_id               = module.eks_blueprints.eks_cluster_id
  eks_cluster_endpoint         = module.eks_blueprints.eks_cluster_endpoint
  eks_oidc_provider            = module.eks_blueprints.oidc_provider
  eks_cluster_version          = module.eks_blueprints.eks_cluster_version
  eks_worker_security_group_id = module.eks_blueprints.worker_node_security_group_id
  auto_scaling_group_names     = module.eks_blueprints.self_managed_node_group_autoscaling_groups
  
  # Wait on the `kube-system` profile before provisioning addons
  data_plane_wait_arn = module.eks_blueprints.fargate_profiles["kube_system"].eks_fargate_profile_arn
  
  # EKS Addons
  enable_amazon_eks_vpc_cni = true
  amazon_eks_vpc_cni_config = {
    most_recent = true
  }

  enable_amazon_eks_kube_proxy = true
  amazon_eks_kube_proxy_config = {
    most_recent = true
  }

  enable_self_managed_coredns                    = true
  remove_default_coredns_deployment              = true
  enable_coredns_cluster_proportional_autoscaler = false
  self_managed_coredns_helm_config = {
    # Sets the correct annotations to ensure the Fargate provisioner is used and not the EC2 provisioner
    compute_type       = "fargate"
    kubernetes_version = module.eks_blueprints.eks_cluster_version
  }

  # Sample application
  enable_app_2048 = false
  
  #prometheus 

  enable_prometheus                    = true
  enable_amazon_eks_aws_ebs_csi_driver = true
  enable_amazon_prometheus             = true
  amazon_prometheus_workspace_endpoint = module.managed_prometheus.workspace_prometheus_endpoint

 
  #enable aws managed grafana 

  enable_aws_managed_grafana = true
  aws_managed_grafana_terraform_config = {
      
        name                      = local.name
        associate_license         = false
        description               = "aws managed grafana"
        account_access_type       = "CURRENT_ACCOUNT"
        authentication_providers  = ["AWS_SSO"]
        permission_type           = "SERVICE_MANAGED"
        data_sources              = ["CLOUDWATCH", "PROMETHEUS", "XRAY"]
        notification_destinations = ["SNS"]
        stack_set_name            = local.name
        role_associations         = { role         = "ADMIN"
                                      user_ids     = ["vd"]
                                    }
  }


  #fluentbit for aws 

  enable_aws_for_fluentbit                 = true
  aws_for_fluentbit_cw_log_group_retention = 30
  aws_for_fluentbit_helm_config = {
    create_namespace = true
    compute_type       = "fargate" 
  }

  enable_kyverno                 = false
  enable_kyverno_policies        = false
  enable_kyverno_policy_reporter = false

  # Enable Fargate logging
  enable_fargate_fluentbit = false
  fargate_fluentbit_addon_config = {
    flb_log_cw = true
  }

  enable_aws_load_balancer_controller = true
  aws_load_balancer_controller_helm_config = {
    set_values = [
      {
        name  = "vpcId"
        value = module.vpc.vpc_id
      },
      {
        name  = "podDisruptionBudget.maxUnavailable"
        value = 1
      },
    ]
  }

  enable_argocd = true
    # This example shows how to set default ArgoCD Admin Password using SecretsManager with Helm Chart set_sensitive values.
   #/
    argocd_helm_config = {
      set_sensitive = [
        {
          name  = "configs.secret.argocdServerAdminPassword"
          value = bcrypt_hash.argo.id
        }
      ]
    }


  argocd_manage_add_ons = false #BUG : Enables the ingress controller # Indicates that ArgoCD is responsible for managing/deploying add-ons
  
  argocd_applications = {
    /*
    addons = {
      path               = "chart"
      repo_url           = "https://github.com/aws-samples/eks-blueprints-add-ons.git"
      add_on_application = true
    } 
    */

    workloads = {
      path               = "multi-repo/argo-app-of-apps/dev"
      repo_url           = "https://github.com/PeculiarGideon/eks-blueprints-workloads_gi"
      add_on_application = false
    }
  } 

  tags = local.tags
}

#---------------------------------------------------------------
# ArgoCD Admin Password credentials with Secrets Manager
# Login to AWS Secrets manager with the same role as Terraform to extract the ArgoCD admin password with the secret name as "argocd"
#---------------------------------------------------------------
resource "random_password" "argocd" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Argo requires the password to be bcrypt, we use custom provider of bcrypt,
# as the default bcrypt function generates diff for each terraform plan
resource "bcrypt_hash" "argo" {
  cleartext = random_password.argocd.result
}

#tfsec:ignore:aws-ssm-secret-use-customer-key
resource "aws_secretsmanager_secret" "arogcd" {
  name                    = "argocd+${module.eks_blueprints.eks_cluster_id}"
  recovery_window_in_days = 0 # Set to zero for this example to force delete during Terraform destroy
}

resource "aws_secretsmanager_secret_version" "arogcd" {
  secret_id     = aws_secretsmanager_secret.arogcd.id
  secret_string = random_password.argocd.result
}

#---------------------------------------------------------------
# ADOT 
#--------------------------------------------------------------
/*
module "adot-amp-grafana-for-java" {
  source = "../observability/adot-amp-grafana-for-java_vik"
  
  grafana_endpoint ="https://g-af97f4fce9.grafana-workspace.us-east-1.amazonaws.com/?orgId=1"
  grafana_api_key      = "eyJrIjoiQ3hNdU5jVFlvdjQwc1lUU0NkeEQ5RFY3aXJ0WDFCWlMiLCJuIjoiYWRvdCIsImlkIjoxfQ=="
  aws_region = local.region

  
  adot_java_config = {
      
      vpc_id             = module.vpc.vpc_id
      private_subnet_ids = module.vpc.private_subnets
      eks_cluster_id       = module.eks_blueprints.eks_cluster_id
      eks_cluster_endpoint = module.eks_blueprints.eks_cluster_endpoint
      oidc_provider    = module.eks_blueprints.oidc_provider
      eks_cluster_version  = module.eks_blueprints.eks_cluster_version
      name                 = local.name
      workspace_prometheus_endpoint = module.managed_prometheus.workspace_prometheus_endpoint

      
  }
  

}

*/

#---------------------------------------------------------------
# Supporting Resources
#---------------------------------------------------------------
module "managed_prometheus" {
  source  = "terraform-aws-modules/managed-service-prometheus/aws"
  version = "~> 2.1"

  workspace_alias = local.name

  tags = local.tags
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
  }

  tags = local.tags
}
