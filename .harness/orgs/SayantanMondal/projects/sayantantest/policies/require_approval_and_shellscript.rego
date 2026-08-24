package pipeline

# Deny pipelines that do not have a HarnessApproval step
deny[msg] {
  not has_approval_step
  msg := "Pipeline must contain at least one HarnessApproval step"
}

# Deny pipelines that do not have a ShellScript step
deny[msg] {
  not has_shellscript_step
  msg := "Pipeline must contain at least one ShellScript step"
}

# Check for HarnessApproval step anywhere in the pipeline
has_approval_step {
  [_, value] = walk(input.pipeline)
  value.type == "HarnessApproval"
}

# Check for ShellScript step anywhere in the pipeline
has_shellscript_step {
  [_, value] = walk(input.pipeline)
  value.type == "ShellScript"
}