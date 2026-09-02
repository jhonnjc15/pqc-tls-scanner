import ssl

ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
print("Groups")
print(ctx.get_groups(include_aliases=True))
