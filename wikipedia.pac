

function FindProxyForURL(url, host)
{
  if (dnsDomainIs(host, "wikipedia.org") || shExpMatch(host, "*.wikipedia.org")) {
    return "PROXY 127.0.0.1:8080"; // Replace with your proxy's IP and port
  }

  return "DIRECT";
}
