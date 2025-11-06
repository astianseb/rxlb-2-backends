
locals {
  zone-b = "${var.region_a}-b"
  zone-c = "${var.region_b}-c"
}

provider "google" {
  region = var.region
}

resource "random_id" "id" {
  byte_length = 2
  prefix      = "sg"
}

data "google_project" "producer" {
    project_id = var.sg_project_id
}


resource "google_project_service" "service" {
  for_each = toset([
    "compute.googleapis.com"
  ])

  service            = each.key
  project            = data.google_project.producer.project_id
  disable_on_destroy = false
}


####### VPC NETWORK

resource "google_compute_network" "vpc_network" {
  name                    = "${random_id.id.hex}-vpc"
  auto_create_subnetworks = false
  mtu                     = 1460
  project                 = data.google_project.producer.project_id
}


####### VPC SUBNETS

resource "google_compute_subnetwork" "sb-subnet-a" {
  name          = "subnet-a"
  project       = data.google_project.producer.project_id
  ip_cidr_range = "10.10.20.0/24"
  network       = google_compute_network.vpc_network.id
}

resource "google_compute_subnetwork" "sb-subnet-b" {
  name          = "subnet-b"
  project       = data.google_project.producer.project_id
  ip_cidr_range = "10.10.40.0/24"
  network       = google_compute_network.vpc_network.id
}

resource "google_compute_subnetwork" "sb-subnet-c" {
  name          = "subnet-c"
  project       = data.google_project.producer.project_id
  ip_cidr_range = "10.10.50.0/24"
  network       = google_compute_network.vpc_network.id
}

resource "google_compute_subnetwork" "proxy" {
  name          = "proxy"
  project       = data.google_project.producer.project_id
  region        = var.region
  ip_cidr_range = "10.10.100.0/24"
  network       = google_compute_network.vpc_network.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"


}

####### FIREWALL

resource "google_compute_firewall" "fw-allow-internal" {
  name      = "allow-internal"
  project   = data.google_project.producer.project_id
  network   = google_compute_network.vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [google_compute_subnetwork.sb-subnet-a.ip_cidr_range,
  google_compute_subnetwork.sb-subnet-b.ip_cidr_range]
}

resource "google_compute_firewall" "fw-allow-ssh" {
  name      = "allow-ssh"
  project   = data.google_project.producer.project_id
  network   = google_compute_network.vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "fw-app-allow-http" {
  name      = "app-allow-http"
  project   = data.google_project.producer.project_id
  network   = google_compute_network.vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080"]
  }
  target_tags   = ["lb-backend"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "fw-app-allow-health-check" {
  name      = "app-allow-health-check"
  project   = data.google_project.producer.project_id
  network   = google_compute_network.vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }
  target_tags   = ["lb-backend"]
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
}

#### NAT

resource "google_compute_router" "router" {
  name    = "nat-router"
  project = data.google_project.producer.project_id
  network = google_compute_network.vpc_network.id

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "nat" {
  name                               = "my-router-nat"
  project                            = data.google_project.producer.project_id
  router                             = google_compute_router.router.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}


resource "google_compute_region_health_check" "tcp-health-check" {
  name               = "${random_id.id.hex}-tcp-health-check"
  project            = data.google_project.producer.project_id
  region             = var.region 
  timeout_sec        = 1
  check_interval_sec = 1


  tcp_health_check {
    port = "443"
  }
}


// ------------- Instance Group A
resource "google_compute_instance_template" "tmpl-instance-group-1" {
  name                 = "${random_id.id.hex}-ig-1"
  project              = data.google_project.producer.project_id
  description          = "SG instance group of preemptible hosts"
  instance_description = "description assigned to instances"
  machine_type         = "e2-medium"
  can_ip_forward       = false
  tags                 = ["lb-backend"]

  scheduling {
    preemptible       = true
    automatic_restart = false

  }

  // Create a new boot disk from an image
  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network            = google_compute_network.vpc_network.name
    subnetwork         = google_compute_subnetwork.sb-subnet-a.name
    subnetwork_project = data.google_project.producer.project_id
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    #startup-script-url = "gs://cloud-training/gcpnet/ilb/startup.sh"
    startup-script-url = "https://raw.githubusercontent.com/astianseb/sg-helper-scripts/refs/heads/main/startup.sh"
  }
}

#MIG-a
resource "google_compute_instance_group_manager" "grp-instance-group-1" {
  name               = "${random_id.id.hex}-ig-1"
  project            = data.google_project.producer.project_id
  base_instance_name = "mig-a"
  zone               = local.zone-b
  version {
    instance_template = google_compute_instance_template.tmpl-instance-group-1.id
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.tcp-health-check.id
    initial_delay_sec = 300
  }
  named_port {
    name = "sg-https"
    port = 443
  }
}

resource "google_compute_autoscaler" "obj-my-autoscaler-a" {
  name    = "${random_id.id.hex}-autoscaler-a"
  project = data.google_project.producer.project_id
  zone    = local.zone-b
  target  = google_compute_instance_group_manager.grp-instance-group-1.id

  autoscaling_policy {
    max_replicas    = 5
    min_replicas    = 1
    cooldown_period = 45

    cpu_utilization {
      target = 0.8
    }
  }
}


//----------------Instance Group B

resource "google_compute_instance_template" "tmpl-instance-group-2" {
  name                 = "${random_id.id.hex}-ig-2"
  project              = data.google_project.producer.project_id
  description          = "SG instance group of preemptible hosts"
  instance_description = "description assigned to instances"
  machine_type         = "e2-medium"
  can_ip_forward       = false
  tags                 = ["lb-backend"]

  scheduling {
    preemptible       = true
    automatic_restart = false

  }

  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network            = google_compute_network.vpc_network.name
    subnetwork         = google_compute_subnetwork.sb-subnet-b.name
    subnetwork_project = data.google_project.producer.project_id
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  
  metadata = {
    startup-script-url = "https://raw.githubusercontent.com/astianseb/sg-helper-scripts/refs/heads/main/startup.sh"
    #startup-script-url = "gs://cloud-training/gcpnet/ilb/startup.sh"
  }
}

resource "google_compute_instance_group_manager" "grp-instance-group-2" {
  name               = "${random_id.id.hex}-ig-2"
  project            = data.google_project.producer.project_id
  base_instance_name = "mig-b"
  zone               = local.zone-c
  version {
    instance_template = google_compute_instance_template.tmpl-instance-group-2.id
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.tcp-health-check.id
    initial_delay_sec = 300
  }
  named_port {
    name = "sg-https"
    port = 443
  }
}

resource "google_compute_autoscaler" "obj-my-autoscaler-b" {
  name    = "${random_id.id.hex}-autoscaler-b"
  project = data.google_project.producer.project_id
  zone    = local.zone-c
  target  = google_compute_instance_group_manager.grp-instance-group-2.id

  autoscaling_policy {
    max_replicas    = 5
    min_replicas    = 1
    cooldown_period = 45

    cpu_utilization {
      target = 0.8
    }
  }
}


# reserved IP address
resource "google_compute_address" "default" {
  provider     = google-beta
  network_tier = "STANDARD"
  region       = var.region
  project      = data.google_project.producer.project_id
  name         = "${random_id.id.hex}-ext-ip"
}


# forwarding rule
resource "google_compute_forwarding_rule" "default" {
  name                  = "${var.sg_prefix}-rxlb-fr"
  #provider              = google-beta
  region                = var.region
  project               = data.google_project.producer.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  network_tier          = "STANDARD"
  target                = google_compute_region_target_https_proxy.default.id
  ip_address            = google_compute_address.default.id
  network               = google_compute_network.vpc_network.id
}

# Self-signed regional SSL certificate for testing
resource "tls_private_key" "producer" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "producer" {
  private_key_pem = tls_private_key.producer.private_key_pem

  # Certificate expires after 48 hours.
  validity_period_hours = 48

  # Generate a new certificate if Terraform is run within three
  # hours of the certificate's expiration time.
  early_renewal_hours = 3

  # Reasonable set of uses for a server SSL certificate.
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = ["sg-test-producer.com"]

  subject {
    common_name  = "sg-test-producer.com"
    organization = "SG Test Producer"
  }
}


resource "google_compute_region_ssl_certificate" "producer" {
  project     = data.google_project.producer.project_id
  name_prefix = "${random_id.id.hex}"
  private_key = tls_private_key.producer.private_key_pem
  certificate = tls_self_signed_cert.producer.cert_pem
  lifecycle {
    create_before_destroy = true
  }
}

# http proxy
resource "google_compute_region_target_https_proxy" "default" {
  name     = "${random_id.id.hex}"
  provider = google-beta
  region   = var.region
  project  = data.google_project.producer.project_id
  url_map  = google_compute_region_url_map.default.id
  
  ssl_certificates = [google_compute_region_ssl_certificate.producer.self_link]

}

# url map
resource "google_compute_region_url_map" "default" {
  name            = "${random_id.id.hex}-rxlb"
  provider        = google-beta
  region          = var.region
  project         = data.google_project.producer.project_id
  default_service = google_compute_region_backend_service.ab.id

  # path_matcher {
  #   name            = "sg-mysite"
  #   default_service = google_compute_region_backend_service.ab.id

  #   path_rule {
  #     paths   = ["/home"]
  #     service = google_compute_region_backend_service.c.id
  #     route_action {
  #       url_rewrite {
  #         path_prefix_rewrite = "/"
  #       }
  #     }
  #   }
  #  }
  #  host_rule {
  #   hosts        = ["mysite.gcp.sebastiang.eu"]
  #   path_matcher = "sg-mysite"
  #  }
}



# backend service with custom request and response headers
resource "google_compute_region_backend_service" "ab" {
  name                     = "backend-service-ab"
  provider                 = google-beta
  region                   = var.region
  project                  = data.google_project.producer.project_id
  protocol                 = "HTTPS"
  port_name                = "sg-https"
  load_balancing_scheme    = "EXTERNAL_MANAGED"
  timeout_sec              = 10
  #enable_cdn               = true
  #custom_request_headers   = ["X-Client-Geo-Location: {client_region_subdivision}, {client_city}"]
  #custom_response_headers  = ["X-Cache-Hit: {cdn_cache_status}"]
  health_checks            = [google_compute_region_health_check.tcp-health-check.id]
  backend {
    group           = google_compute_instance_group_manager.grp-instance-group-1.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
  backend {
    group           = google_compute_instance_group_manager.grp-instance-group-2.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}


# Instance to host siege (testing tool for LB)
# usage: siege -i --concurrent=50 http://<lb-ip>


resource "google_compute_instance" "siege-host" {
  name         = "${random_id.id.hex}-siege-host"
  machine_type = "e2-medium"
  zone         = local.zone-b
  project      = data.google_project.producer.project_id

  tags = ["siege"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.vpc_network.name
    subnetwork = google_compute_subnetwork.sb-subnet-b.self_link
  }

  scheduling {
    preemptible       = true
    automatic_restart = false
  }

  metadata = {
    enable-oslogin = true
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata_startup_script = <<-EOF1
      #! /bin/bash
      set -euo pipefail

      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y siege
     EOF1

}