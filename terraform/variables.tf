variable "lambda_s3_bucket" {
  type = string
}

variable "lambda_s3_key" {
  type = string
}

variable "dns" {
  type = object({
    zone_id = string
    domain = string
  })
  default = null
}
