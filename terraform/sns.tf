# SNS topic for email notifications
resource "aws_sns_topic" "notifications" {
  name = "${var.project_name}-notifications"

  tags = {
    Name = "${var.project_name}-notifications"
  }
}

# Email subscription
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
