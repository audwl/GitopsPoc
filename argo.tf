# ArgoCD 네임스페이스 생성
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = "argocd"
  }
}

# ArgoCD 설치를 위한 매니페스트 적용
resource "null_resource" "apply_argocd_manifests" {
  depends_on = [kubernetes_namespace.argocd]

  provisioner "local-exec" {
    command = <<EOT
      kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
    EOT
  }
}

# ArgoCD 관리자 비밀번호 설정
resource "kubernetes_secret" "argocd_admin_secret" {
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = kubernetes_namespace.argocd.metadata[0].name
  }

  data = {
    password = base64encode("your_admin_password_here")
  }

  type = "Opaque"
}
