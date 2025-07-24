

resource "aws_iam_policy" "gitlab_runner_policy" {
  name        = "gitlab-runner-role-policy"
  description = "Permissions for GitLab Runner cross-account role"
  policy      = data.aws_iam_policy_document.gitlab_runner.json
}


resource "aws_iam_role_policy_attachment" "cross_account_attachment" {
  role       = "cicd-cross-account-dca752-role"  
  policy_arn = aws_iam_policy.gitlab_runner_policy.arn
}

data "aws_iam_policy_document" "gitlab_runner" {
  statement {
    sid = "codedeploy0"
    actions = [
      "codedeploy:BatchGetApplicationRevisions",
      "codedeploy:BatchGetApplications",
      "codedeploy:BatchGetDeploymentGroups",
      "codedeploy:BatchGetDeploymentInstances",
      "codedeploy:BatchGetDeployments",
      "codedeploy:BatchGetOnPremisesInstances",
      "codedeploy:CreateDeployment",
      "codedeploy:GetApplication",
      "codedeploy:GetApplicationRevision",
      "codedeploy:GetDeployment",
      "codedeploy:GetDeploymentConfig",
      "codedeploy:GetDeploymentGroup",
      "codedeploy:GetDeploymentInstance",
      "codedeploy:GetOnPremisesInstance",
      "codedeploy:ListApplicationRevisions",
      "codedeploy:ListDeploymentGroups",
      "codedeploy:ListDeploymentInstances",
      "codedeploy:ListDeployments",
      "codedeploy:ListTagsForResource",
      "codedeploy:RegisterApplicationRevision"
    ]
    resources = [
      "arn:aws-us-gov:codedeploy:*:190056725169:application:*",
      "arn:aws-us-gov:codedeploy:*:190056725169:deploymentconfig:*",
      "arn:aws-us-gov:codedeploy:*:190056725169:deploymentgroup:*/*",
      "arn:aws-us-gov:codedeploy:*:190056725169:instance:*"
    ]
  }

  statement {
    sid = "codedeploy1"
    actions = [
      "codedeploy:BatchGetDeploymentTargets",
      "codedeploy:GetDeploymentTarget",
      "codedeploy:ListApplications",
      "codedeploy:ListDeploymentConfigs",
      "codedeploy:ListDeploymentTargets",
      "codedeploy:ListGitHubAccountTokenNames",
      "codedeploy:ListOnPremisesInstances",
      "codedeploy:StopDeployment"
    ]
    resources = ["*"]
  }

  statement {
    sid = "awsbackup"
    actions = ["backup:*"]
    resources = [
      "arn:aws-us-gov:backup:*:190056725169:framework:*-*",
      "arn:aws-us-gov:backup:*:190056725169:report-plan:*-*",
      "arn:aws-us-gov:backup:*:190056725169:backup-vault:*",
      "arn:aws-us-gov:backup:*:190056725169:backup-plan:*",
      "arn:aws-us-gov:backup:*:190056725169:legal-hold:*",
      "arn:aws-us-gov:backup:*:190056725169:recovery-point:*"
    ]
  }
#checked til here
  statement {
    sid = "autoscaling"
    actions = [
      "autoscaling:DeleteLifecycleHook",
      "autoscaling:SetDesiredCapacity",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:StartInstanceRefresh",
      "autoscaling:RollbackInstanceRefresh",
      "autoscaling:CancelInstanceRefresh",
      "autoscaling:EnterStandby",
      "autoscaling:ExitStandby",
      "autoscaling:TerminateInstanceInAutoScalingGroup"
    ]
    resources = ["arn:aws-us-gov:autoscaling:${data.aws_caller_identity.current.account_id}:autoScalingGroup:*"]
  }

  statement {
    sid = "describeasg"
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLifecycleHooks",
      "autoscaling:DescribeInstanceRefreshes"
    ]
    resources = ["*"]
  }

  statement {
    sid = "efs"
    actions   = ["elasticfilesystem:DeleteFileSystem"]
    resources = ["arn:aws-us-gov:elasticfilesystem:${data.aws_caller_identity.current.account_id}:file-system/*"]
  }

  statement {
    sid = "ecs"
    actions = [
      "ecs:ExecuteCommand",
      "ecs:CreateCapacityProvider",
      "ecs:CreateCluster",
      "ecs:CreateTaskSet",
      "ecs:DeleteAccountSetting",
      "ecs:DeregisterTaskDefinition",
      "ecs:DescribeTaskDefinition",
      "ecs:DiscoverPollEndpoint",
      "ecs:ListAccountSettings",
      "ecs:ListClusters",
      "ecs:ListServices",
      "ecs:ListTaskDefinitionFamilies",
      "ecs:ListTaskDefinitions",
      "ecs:PutAccountSetting",
      "ecs:PutAccountSettingDefault",
      "ecs:RegisterTaskDefinition"
    ]
    resources = [
      "arn:aws-us-gov:ecs:${data.aws_caller_identity.current.account_id}:cluster/*",
      "arn:aws-us-gov:ecs:${data.aws_caller_identity.current.account_id}:task/*"
    ]
  }

  statement {
    sid       = "iam"
    actions   = ["iam:DetachRolePolicy"]
    resources = ["arn:aws-us-gov:iam:${data.aws_caller_identity.current.account_id}:role/*"]
  }

  statement {
    sid = "ecr"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:ListTagsForResource",
      "ecr:DescribeImageScanFindings",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage"
    ]
    resources = ["*"]
  }
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}