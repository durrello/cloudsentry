# SES Email Identity verification
# This sends verification emails automatically on deploy.
# Users still need to click the link in their inbox.
resource "aws_ses_email_identity" "notification_emails" {
  for_each = toset(var.notification_emails)
  email    = each.value
}
