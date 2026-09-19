resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# GuardRail publishes to the account's default EventBridge bus, so no
# separate bus resource is required — kept here as a placeholder in case
# you want to isolate GuardRail events onto their own bus later.
data "aws_cloudwatch_event_bus" "default" {
  name = "default"
}
