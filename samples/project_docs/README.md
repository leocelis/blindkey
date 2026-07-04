# SAMPLE project_docs — SYNTHETIC TEST DATA. NOT REAL FILES.
#
# A realistically-shaped mini project folder so `vault seal` can be exercised:
# a fake .env, a fake contract note, and a nested config — the kind of tree a
# developer would seal before dropping it on Dropbox/Drive/S3.
# Every value is randomly generated and marked FAKE/EXAMPLE.
# Try it:  vault seal samples/project_docs        → project_docs.vltf
#          vault peek project_docs.vltf           → inner tree (post-unlock)
#          vault open project_docs.vltf -C /tmp/x → restore
