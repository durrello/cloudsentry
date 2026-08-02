# CloudFront distribution for the HTML dashboard
# Point cloudsentry.durrellgemuh.com to this distribution via Cloudflare DNS

resource "aws_cloudfront_origin_access_control" "dashboard" {
  name                              = "${var.project_name}-dashboard-oac"
  description                       = "OAC for CloudSentry dashboard S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "dashboard" {
  enabled             = true
  default_root_object = "reports/latest.html"
  comment             = "CloudSentry Dashboard"
  price_class         = "PriceClass_100" # US, Canada, Europe only (cheapest)

  aliases = var.dashboard_domain != "" ? [var.dashboard_domain] : []

  origin {
    domain_name              = aws_s3_bucket.dashboard.bucket_regional_domain_name
    origin_id                = "s3-dashboard"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-dashboard"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600  # 1 hour cache
    max_ttl     = 86400 # 1 day max
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    # Use CloudFront default cert if no custom domain
    # For custom domain via Cloudflare, Cloudflare handles SSL
    cloudfront_default_certificate = var.dashboard_domain == "" ? true : false
    # If using custom domain with ACM cert:
    acm_certificate_arn      = var.dashboard_acm_cert_arn != "" ? var.dashboard_acm_cert_arn : null
    ssl_support_method       = var.dashboard_acm_cert_arn != "" ? "sni-only" : null
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    Name = "${var.project_name}-dashboard-cdn"
  }
}

# S3 bucket policy to allow CloudFront access
resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.dashboard.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.dashboard.arn
          }
        }
      }
    ]
  })
}
