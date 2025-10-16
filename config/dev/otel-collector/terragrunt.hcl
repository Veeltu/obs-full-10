include "root" {
  path = ("../root.hcl")
  # path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../stacks/otel-collector"
  # source = "${get_path_to_repo_root()}//stacks/otel-collector"
}

inputs = {
}
