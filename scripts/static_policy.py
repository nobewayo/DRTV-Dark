"""Static execution policy shared by artifact verification."""
CSP="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; font-src 'self'; worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"


def require(ok,message):
    if not ok:raise ValueError(message)
