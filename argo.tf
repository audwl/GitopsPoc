provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.k8s.token
}

data "aws_eks_cluster_auth" "k8s" {
  name = module.eks.cluster_name
}

# ArgoCD 네임스페이스 생성
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = "argocd"
  }
}

# ArgoCD 설치를 위한 Helm Provider 설정
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# ArgoCD 설치를 위한 Helm 차트 적용
resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = "latest"

  set {
    name  = "server.service.type"
    value = "LoadBalancer"
  }

  set {
    name  = "installCRDs"
    value = "true"
  }

  namespace        = "argocd"  # 이미 생성된 네임스페이스 사용
  create_namespace = false     # 이미 네임스페이스가 생성되었으므로 false로 설정
}

# ArgoCD 관리자 비밀번호 설정
resource "kubernetes_secret" "argocd_admin_secret" {
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = "argocd"  # 수동으로 생성한 네임스페이스를 사용
  }

  data = {
    password = base64encode("your_admin_password_here")
  }

  type = "Opaque"
}
