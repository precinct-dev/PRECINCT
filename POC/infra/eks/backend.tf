# ------------------------------------------------------------------------------
# Remote State Backend -- S3 + DynamoDB
#
# BOOTSTRAPPING: This is commented out by default. To use remote state:
#
#   1. Create the S3 bucket:
#      aws s3api create-bucket \
#        --bucket agentic-ref-arch-tfstate \
#        --region us-west-2 \
#        --create-bucket-configuration LocationConstraint=us-west-2
#
#   2. Enable versioning:
#      aws s3api put-bucket-versioning \
#        --bucket agentic-ref-arch-tfstate \
#        --versioning-configuration Status=Enabled
#
#   3. Create the DynamoDB lock table:
#      aws dynamodb create-table \
#        --table-name terraform-lock \
#        --attribute-definitions AttributeName=LockID,AttributeType=S \
#        --key-schema AttributeName=LockID,KeyType=HASH \
#        --billing-mode PAY_PER_REQUEST \
#        --region us-west-2
#
#   4. Uncomment the block below and run: tofu init
# ------------------------------------------------------------------------------

# terraform {
#   backend "s3" {
#     bucket         = "agentic-ref-arch-tfstate"
#     key            = "eks/terraform.tfstate"
#     region         = "us-west-2"
#     dynamodb_table = "terraform-lock"
#     encrypt        = true
#   }
# }
