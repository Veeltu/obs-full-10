locals {
  docker_repositories = {
    # https://console.cloud.google.com/artifacts?referrer=search&project=nz-mgmt-shared-artifacts-8c85
    # quay_io         = "artifactory.ctn-e.test.pndrs.de/docker"
    # edp_docker      = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/edp-docker"
    # docker_hub      = "artifactory.ctn-e.test.pndrs.de/docker"

    # quay_io         = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/quay-io"
    # edp_docker      = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/edp-docker"
    docker_hub      = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/docker-hub"
    # ghcr_io      = "europe-west3-docker.pkg.dev/nz-mgmt-shared-artifacts-8c85/ghcr-io"
  }
  # project = "nzd-smanke-res-ehay"
  # cluster = {
  #   name     = "smanke-resource-automation"
  #   location = "europe-west3"
  # }

  # # we may still move this to another location!
  # tfstate_bucket             = "tf-state-bucket-landingzone-cloud-mgmt-dev"
  # tfstate_prefix             = "terraform/state/observability-poc"
  # location                   = "europe-west3"
}
