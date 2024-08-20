# ECR 리포지토리 생성
resource "aws_ecr_repository" "petclinic_repo" {
  name = "petclinic-repo"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "petclinic-ecr-repo"
  }
}

# ECR에 대한 IAM 정책을 연결하는 역할
resource "aws_iam_role_policy_attachment" "ecr_access" {
  role       = aws_iam_role.myungji_eks_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
}
