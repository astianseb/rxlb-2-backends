
# output "project_id" {
#   value = data.google_project.producer.project_id
# }

# # output "loadbalancer_external_ip" {
# #   value = google_compute_global_address.default.address
# # }

# output "siege_command" {
#   value = "siege -i --concurrent=50 http://${google_compute_global_address.default.address}"
# }

# output "ssh_to_siege_host" {
#   value = <<EOT1
#     gcloud compute ssh --zone "${google_compute_instance.siege-host.zone}" "${google_compute_instance.siege-host.name}"  --tunnel-through-iap --project "${google_compute_instance.siege-host.project}"
#     EOT1
# }

# output "how_to_use" {
#   value = <<EOT2
#     Please log into a siege host by issuing command:
#     gcloud compute ssh --zone "${google_compute_instance.siege-host.zone}" "${google_compute_instance.siege-host.name}"  --tunnel-through-iap --project "${google_compute_instance.siege-host.project}"
#     Once logged in, please start a siege on a load balancer external IP address:
#     siege -i --concurrent=50 http://${google_compute_global_address.default.address}
#     EOT2
# }