/*
 * RFC 8291 Appendix A vector test for webpush_crypto.h
 * Build (from inspircd4/): g++ -O2 -o test_webpush_crypto test_webpush_crypto.cpp -lcrypto
 */

#include "m_ircv3_webpush/webpush_crypto.h"

#include <cstdio>
#include <cstdlib>

static std::string MustB64(const char* s)
{
	std::string out;
	if (!WebPush::B64Decode(s, out))
	{
		std::fprintf(stderr, "b64 decode failed: %s\n", s);
		std::exit(1);
	}
	return out;
}

static void ExpectHex(const char* name, const std::string& got, const std::string& want)
{
	if (got == want)
	{
		std::printf("ok  %s (%zu bytes)\n", name, got.size());
		return;
	}
	std::fprintf(stderr, "FAIL %s: got %s want %s\n", name,
		WebPush::B64Encode(got, WebPush::B64URL, false).c_str(),
		WebPush::B64Encode(want, WebPush::B64URL, false).c_str());
	std::exit(1);
}

int main()
{
	const std::string plaintext = MustB64("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
	const std::string as_public = MustB64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
	const std::string as_private = MustB64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw");
	const std::string ua_public = MustB64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
	const std::string salt = MustB64("DGv6ra1nlYgDCS1FRnbzlw");
	const std::string auth_secret = MustB64("BTBZMqHH6r4Tts7J_aSIgg");
	const std::string want_ecdh = MustB64("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
	const std::string want_ikm = MustB64("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
	const std::string want_cek = MustB64("oIhVW04MRdy2XN9CiKLxTg");
	const std::string want_nonce = MustB64("4h_95klXJ5E_qnoN");
	const std::string want_header = MustB64("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
	const std::string want_ct = MustB64("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ");

	if (plaintext != "When I grow up, I want to be a watermelon")
	{
		std::fprintf(stderr, "plaintext mismatch\n");
		return 1;
	}

	EVP_PKEY* as_key = WebPush::EvpFromPrivateRaw(
		reinterpret_cast<const unsigned char*>(as_private.data()), as_private.size(),
		reinterpret_cast<const unsigned char*>(as_public.data()), as_public.size());
	if (!as_key)
	{
		std::fprintf(stderr, "failed to load as_key (priv=%zu): %s\n",
			as_private.size(), WebPush::OpenSSLError().c_str());
		return 1;
	}
	EVP_PKEY* ua_key = WebPush::EvpFromUncompressed(
		reinterpret_cast<const unsigned char*>(ua_public.data()), ua_public.size());
	if (!ua_key)
	{
		std::fprintf(stderr, "failed to load ua_key\n");
		return 1;
	}

	std::string ecdh;
	if (!WebPush::EcdhX(as_key, ua_key, ecdh))
	{
		std::fprintf(stderr, "ECDH failed: %s\n", WebPush::OpenSSLError().c_str());
		return 1;
	}
	ExpectHex("ecdh_secret", ecdh, want_ecdh);

	std::string key_info = "WebPush: info";
	key_info.push_back('\0');
	key_info.append(ua_public);
	key_info.append(as_public);
	unsigned char ikm[32];
	if (!WebPush::HkdfSha256(reinterpret_cast<const unsigned char*>(auth_secret.data()), auth_secret.size(),
		reinterpret_cast<const unsigned char*>(ecdh.data()), ecdh.size(),
		reinterpret_cast<const unsigned char*>(key_info.data()), key_info.size(), ikm, 32))
	{
		std::fprintf(stderr, "HKDF ikm failed\n");
		return 1;
	}
	ExpectHex("IKM", std::string(reinterpret_cast<char*>(ikm), 32), want_ikm);

	static const unsigned char cek_info[] = "Content-Encoding: aes128gcm";
	static const unsigned char nonce_info[] = "Content-Encoding: nonce";
	unsigned char cek[16];
	unsigned char nonce[12];
	if (!WebPush::HkdfSha256(reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), ikm, 32,
			cek_info, sizeof(cek_info), cek, 16)
		|| !WebPush::HkdfSha256(reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), ikm, 32,
			nonce_info, sizeof(nonce_info), nonce, 12))
	{
		std::fprintf(stderr, "HKDF cek/nonce failed\n");
		return 1;
	}
	ExpectHex("CEK", std::string(reinterpret_cast<char*>(cek), 16), want_cek);
	ExpectHex("NONCE", std::string(reinterpret_cast<char*>(nonce), 12), want_nonce);

	std::printf("… pubkey export\n");
	std::string as_pub_probe;
	if (!WebPush::EvpPublicUncompressed(as_key, as_pub_probe))
	{
		std::fprintf(stderr, "EvpPublicUncompressed failed: %s\n", WebPush::OpenSSLError().c_str());
		return 1;
	}
	ExpectHex("as_public_export", as_pub_probe, as_public);

	std::printf("… encrypt\n");
	std::string body;
	std::string as_pub_out;
	if (!WebPush::EncryptAes128Gcm(plaintext, ua_public, auth_secret, body, &as_pub_out,
		reinterpret_cast<const unsigned char*>(salt.data()), as_key))
	{
		std::fprintf(stderr, "EncryptAes128Gcm failed: %s\n", WebPush::OpenSSLError().c_str());
		return 1;
	}
	std::printf("… encrypt done\n");
	ExpectHex("as_public", as_pub_out, as_public);
	if (body.size() < 86)
	{
		std::fprintf(stderr, "body too short\n");
		return 1;
	}
	ExpectHex("header", body.substr(0, 86), want_header);
	ExpectHex("ciphertext", body.substr(86), want_ct);
	ExpectHex("full body", body, want_header + want_ct);

	EVP_PKEY_free(as_key);
	EVP_PKEY_free(ua_key);

	WebPush::VapidKeys vapid;
	if (!WebPush::GenerateVapid(vapid) || vapid.public_uncompressed.size() != 65)
	{
		std::fprintf(stderr, "GenerateVapid failed\n");
		return 1;
	}
	std::string jwt;
	if (!WebPush::JwtEs256(vapid.pkey, "https://push.example.net", "mailto:webpush@example.net",
		time(nullptr) + 3600, jwt) || jwt.find('.') == std::string::npos)
	{
		std::fprintf(stderr, "JwtEs256 failed\n");
		return 1;
	}
	std::printf("ok  VAPID JWT (%zu chars)\n", jwt.size());

	std::string host, port, path;
	if (!WebPush::ParseHttpsUrl("https://fcm.googleapis.com/fcm/send/abc", host, port, path)
		|| host != "fcm.googleapis.com" || port != "443" || path != "/fcm/send/abc")
	{
		std::fprintf(stderr, "ParseHttpsUrl failed\n");
		return 1;
	}
	if (WebPush::ParseHttpsUrl("http://example.com/", host, port, path)
		|| WebPush::ParseHttpsUrl("https://127.0.0.1/", host, port, path) == false)
	{
		// http must fail; 127.0.0.1 URL parses but is blocked at connect
	}
	if (WebPush::ParseHttpsUrl("http://evil.test/", host, port, path))
	{
		std::fprintf(stderr, "http url must be rejected\n");
		return 1;
	}
	if (WebPush::OriginOf("https://fcm.googleapis.com/fcm/send/x") != "https://fcm.googleapis.com")
	{
		std::fprintf(stderr, "OriginOf failed\n");
		return 1;
	}
	if (WebPush::HostIsInternalLiteral("127.0.0.1") == false
		|| WebPush::HostIsInternalLiteral("10.0.0.1") == false
		|| WebPush::HostIsInternalLiteral("192.168.1.1") == false
		|| WebPush::HostIsInternalLiteral("8.8.8.8") == true
		|| WebPush::HostIsInternalLiteral("fcm.googleapis.com") == true)
	{
		std::fprintf(stderr, "HostIsInternalLiteral failed\n");
		return 1;
	}
	std::printf("ok  URL parser / SSRF literals\n");
	std::printf("all rfc8291 vectors passed\n");
	return 0;
}
