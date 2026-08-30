/*
 * Web Push helpers for InspIRCd m_ircv3_webpush (RFC 8030, RFC 8188, RFC 8291, RFC 8292).
 *
 * OpenSSL 1.1.1+ / 3.x. No InspIRCd dependency — used by the module and the
 * RFC 8291 vector test.
 */

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#ifndef OPENSSL_SUPPRESS_DEPRECATED
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#ifndef _WIN32
# include <arpa/inet.h>
# include <fcntl.h>
# include <netdb.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <unistd.h>
#else
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

namespace WebPush {

inline constexpr const char* B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
inline constexpr const char* B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline int B64Index(char c, const char* table)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (table[62] == '-' && c == '-')
		return 62;
	if (table[63] == '_' && c == '_')
		return 63;
	if (table[62] == '+' && c == '+')
		return 62;
	if (table[63] == '/' && c == '/')
		return 63;
	return -1;
}

inline std::string B64Encode(const unsigned char* data, size_t len, const char* table, bool pad)
{
	std::string out;
	out.reserve(((len + 2) / 3) * 4);
	unsigned int val = 0;
	int valb = -6;
	for (size_t i = 0; i < len; ++i)
	{
		val = (val << 8) + data[i];
		valb += 8;
		while (valb >= 0)
		{
			out.push_back(table[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
		out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
	if (pad)
	{
		while (out.size() % 4)
			out.push_back('=');
	}
	return out;
}

inline std::string B64Encode(const std::string& data, const char* table, bool pad)
{
	return B64Encode(reinterpret_cast<const unsigned char*>(data.data()), data.size(), table, pad);
}

inline bool B64Decode(const std::string& in, std::string& out)
{
	std::string s = in;
	while (!s.empty() && s.back() == '=')
		s.pop_back();

	const char* table = B64URL;
	if (s.find('+') != std::string::npos || s.find('/') != std::string::npos)
		table = B64STD;

	out.clear();
	out.reserve(s.size() * 3 / 4);
	unsigned int val = 0;
	int valb = -8;
	for (char c : s)
	{
		if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
			continue;
		int idx = B64Index(c, table);
		if (idx < 0)
			return false;
		val = (val << 6) + static_cast<unsigned int>(idx);
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(static_cast<char>((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return true;
}

inline std::string OpenSSLError()
{
	char buf[256];
	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	return buf;
}

inline bool HkdfSha256(const unsigned char* salt, size_t saltlen,
	const unsigned char* ikm, size_t ikmlen,
	const unsigned char* info, size_t infolen,
	unsigned char* out, size_t outlen)
{
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (!pctx)
		return false;
	bool ok = EVP_PKEY_derive_init(pctx) > 0
		&& EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0
		&& EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(saltlen)) > 0
		&& EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikmlen)) > 0
		&& (infolen == 0 || EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(infolen)) > 0)
		&& EVP_PKEY_derive(pctx, out, &outlen) > 0;
	EVP_PKEY_CTX_free(pctx);
	return ok;
}

inline EC_KEY* EcKeyFromUncompressed(const unsigned char* pub, size_t publen)
{
	if (publen != 65 && publen != 33)
		return nullptr;
	EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!key)
		return nullptr;
	const EC_GROUP* group = EC_KEY_get0_group(key);
	EC_POINT* point = EC_POINT_new(group);
	if (!point)
	{
		EC_KEY_free(key);
		return nullptr;
	}
	if (EC_POINT_oct2point(group, point, pub, publen, nullptr) != 1
		|| EC_KEY_set_public_key(key, point) != 1)
	{
		EC_POINT_free(point);
		EC_KEY_free(key);
		return nullptr;
	}
	EC_POINT_free(point);
	return key;
}

inline EC_KEY* EcKeyFromPrivateRaw(const unsigned char* priv, size_t privlen,
	const unsigned char* pub, size_t publen)
{
	if (privlen != 32)
		return nullptr;
	EC_KEY* key = pub ? EcKeyFromUncompressed(pub, publen) : EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!key)
		return nullptr;
	BIGNUM* bn = BN_bin2bn(priv, static_cast<int>(privlen), nullptr);
	if (!bn || EC_KEY_set_private_key(key, bn) != 1)
	{
		BN_free(bn);
		EC_KEY_free(key);
		return nullptr;
	}
	BN_free(bn);
	if (!pub)
	{
		const EC_GROUP* group = EC_KEY_get0_group(key);
		EC_POINT* point = EC_POINT_new(group);
		if (!point || EC_POINT_mul(group, point, EC_KEY_get0_private_key(key), nullptr, nullptr, nullptr) != 1
			|| EC_KEY_set_public_key(key, point) != 1)
		{
			EC_POINT_free(point);
			EC_KEY_free(key);
			return nullptr;
		}
		EC_POINT_free(point);
	}
	return key;
}

inline bool EcPublicUncompressed(EC_KEY* key, std::string& out)
{
	const EC_GROUP* group = EC_KEY_get0_group(key);
	const EC_POINT* point = EC_KEY_get0_public_key(key);
	if (!group || !point)
		return false;
	unsigned char buf[65];
	size_t n = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), nullptr);
	if (n != 65)
		return false;
	out.assign(reinterpret_cast<char*>(buf), n);
	return true;
}

inline bool EcdhX(EC_KEY* local, EC_KEY* peer, std::string& secret)
{
	EVP_PKEY* loc = EVP_PKEY_new();
	EVP_PKEY* rem = EVP_PKEY_new();
	if (!loc || !rem)
	{
		EVP_PKEY_free(loc);
		EVP_PKEY_free(rem);
		return false;
	}
	// Up-ref: EVP_PKEY_set1_EC_KEY increments the EC_KEY refcount.
	if (EVP_PKEY_set1_EC_KEY(loc, local) != 1 || EVP_PKEY_set1_EC_KEY(rem, peer) != 1)
	{
		EVP_PKEY_free(loc);
		EVP_PKEY_free(rem);
		return false;
	}
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(loc, nullptr);
	bool ok = false;
	size_t slen = 32;
	secret.assign(32, '\0');
	if (ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, rem) > 0
		&& EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(&secret[0]), &slen) > 0 && slen == 32)
	{
		ok = true;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(loc);
	EVP_PKEY_free(rem);
	return ok;
}

inline bool Aes128GcmEncrypt(const unsigned char* key, const unsigned char* nonce,
	const unsigned char* pt, size_t ptlen, std::string& ct)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;
	int len = 0;
	int ctlen = 0;
	ct.assign(ptlen + 16, '\0');
	auto* out = reinterpret_cast<unsigned char*>(&ct[0]);
	bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1
		&& EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
		&& EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1
		&& EVP_EncryptUpdate(ctx, out, &len, pt, static_cast<int>(ptlen)) == 1;
	ctlen = len;
	ok = ok && EVP_EncryptFinal_ex(ctx, out + ctlen, &len) == 1;
	ctlen += len;
	ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + ctlen) == 1;
	EVP_CIPHER_CTX_free(ctx);
	if (!ok)
		return false;
	ct.resize(static_cast<size_t>(ctlen) + 16);
	return true;
}

/** RFC 8291 aes128gcm body (header || ciphertext+tag). rs=4096, no extra padding. */
inline bool EncryptAes128Gcm(const std::string& plaintext, const std::string& ua_public,
	const std::string& auth_secret, std::string& body, std::string* as_public_out = nullptr,
	const unsigned char* salt_override = nullptr, EC_KEY* as_key_override = nullptr)
{
	if (ua_public.size() != 65 || ua_public[0] != '\x04' || auth_secret.size() != 16)
		return false;

	unsigned char salt[16];
	if (salt_override)
		memcpy(salt, salt_override, 16);
	else if (RAND_bytes(salt, 16) != 1)
		return false;

	EC_KEY* as_key = as_key_override;
	bool owned = false;
	if (!as_key)
	{
		as_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!as_key || EC_KEY_generate_key(as_key) != 1)
		{
			EC_KEY_free(as_key);
			return false;
		}
		owned = true;
	}

	std::string as_public;
	if (!EcPublicUncompressed(as_key, as_public))
	{
		if (owned)
			EC_KEY_free(as_key);
		return false;
	}
	if (as_public_out)
		*as_public_out = as_public;

	EC_KEY* ua_key = EcKeyFromUncompressed(
		reinterpret_cast<const unsigned char*>(ua_public.data()), ua_public.size());
	if (!ua_key)
	{
		if (owned)
			EC_KEY_free(as_key);
		return false;
	}

	std::string ecdh;
	if (!EcdhX(as_key, ua_key, ecdh))
	{
		EC_KEY_free(ua_key);
		if (owned)
			EC_KEY_free(as_key);
		return false;
	}
	EC_KEY_free(ua_key);
	if (owned)
		EC_KEY_free(as_key);

	std::string key_info = "WebPush: info";
	key_info.push_back('\0');
	key_info.append(ua_public);
	key_info.append(as_public);

	unsigned char ikm[32];
	if (!HkdfSha256(reinterpret_cast<const unsigned char*>(auth_secret.data()), auth_secret.size(),
		reinterpret_cast<const unsigned char*>(ecdh.data()), ecdh.size(),
		reinterpret_cast<const unsigned char*>(key_info.data()), key_info.size(), ikm, 32))
	{
		return false;
	}

	static const unsigned char cek_info[] = "Content-Encoding: aes128gcm";
	static const unsigned char nonce_info[] = "Content-Encoding: nonce";
	unsigned char cek[16];
	unsigned char nonce[12];
	// info strings are NUL-terminated in RFC 8188 (the extra 0x00 is the C string terminator).
	if (!HkdfSha256(salt, 16, ikm, 32, cek_info, sizeof(cek_info), cek, 16)
		|| !HkdfSha256(salt, 16, ikm, 32, nonce_info, sizeof(nonce_info), nonce, 12))
	{
		return false;
	}

	std::string padded = plaintext;
	padded.push_back('\x02');

	std::string ciphertext;
	if (!Aes128GcmEncrypt(cek, nonce,
		reinterpret_cast<const unsigned char*>(padded.data()), padded.size(), ciphertext))
	{
		return false;
	}

	body.clear();
	body.append(reinterpret_cast<char*>(salt), 16);
	body.push_back('\x00');
	body.push_back('\x00');
	body.push_back('\x10');
	body.push_back('\x00'); // record size 4096
	body.push_back(static_cast<char>(as_public.size()));
	body.append(as_public);
	body.append(ciphertext);
	return true;
}

inline EVP_PKEY* EvpFromEc(EC_KEY* ec)
{
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (!pkey)
		return nullptr;
	if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1)
	{
		EVP_PKEY_free(pkey);
		return nullptr;
	}
	return pkey;
}

inline bool DerEcdsaToRaw(const unsigned char* der, size_t derlen, unsigned char rs[64])
{
	const unsigned char* p = der;
	ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(derlen));
	if (!sig)
		return false;
	const BIGNUM* r = nullptr;
	const BIGNUM* s = nullptr;
	ECDSA_SIG_get0(sig, &r, &s);
	bool ok = r && s && BN_bn2binpad(r, rs, 32) == 32 && BN_bn2binpad(s, rs + 32, 32) == 32;
	ECDSA_SIG_free(sig);
	return ok;
}

inline bool JwtEs256(EVP_PKEY* vapid, const std::string& aud, const std::string& sub,
	time_t exp, std::string& jwt)
{
	const std::string header = R"({"typ":"JWT","alg":"ES256"})";
	std::string payload = "{\"aud\":\"" + aud + "\",\"exp\":" + std::to_string(static_cast<long long>(exp))
		+ ",\"sub\":\"" + sub + "\"}";
	std::string signing = B64Encode(header, B64URL, false) + "." + B64Encode(payload, B64URL, false);

	EVP_MD_CTX* md = EVP_MD_CTX_new();
	if (!md)
		return false;
	size_t siglen = 0;
	bool ok = EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, vapid) == 1
		&& EVP_DigestSign(md, nullptr, &siglen,
			reinterpret_cast<const unsigned char*>(signing.data()), signing.size()) == 1;
	std::string der(siglen, '\0');
	ok = ok && EVP_DigestSign(md, reinterpret_cast<unsigned char*>(&der[0]), &siglen,
		reinterpret_cast<const unsigned char*>(signing.data()), signing.size()) == 1;
	EVP_MD_CTX_free(md);
	if (!ok)
		return false;
	der.resize(siglen);
	unsigned char rs[64];
	if (!DerEcdsaToRaw(reinterpret_cast<unsigned char*>(&der[0]), der.size(), rs))
		return false;
	jwt = signing + "." + B64Encode(rs, 64, B64URL, false);
	return true;
}

inline std::string OriginOf(const std::string& url)
{
	// https://host[:port]/...
	if (url.compare(0, 8, "https://") != 0)
		return {};
	size_t hostbegin = 8;
	size_t slash = url.find('/', hostbegin);
	std::string hostport = url.substr(hostbegin, slash == std::string::npos ? std::string::npos : slash - hostbegin);
	if (hostport.empty() || hostport.find('@') != std::string::npos)
		return {};
	if (!hostport.empty() && hostport.back() == ':')
		return {};
	// Strip default port 443.
	size_t colon = std::string::npos;
	if (hostport[0] == '[')
	{
		size_t rb = hostport.find(']');
		if (rb == std::string::npos)
			return {};
		colon = hostport.find(':', rb);
	}
	else
		colon = hostport.rfind(':');
	if (colon != std::string::npos && hostport.substr(colon) == ":443")
		hostport.erase(colon);
	return "https://" + hostport;
}

struct VapidKeys
{
	EVP_PKEY* pkey = nullptr;
	std::string public_uncompressed;
	std::string public_b64url;

	VapidKeys() = default;
	VapidKeys(const VapidKeys&) = delete;
	VapidKeys& operator=(const VapidKeys&) = delete;
	~VapidKeys()
	{
		EVP_PKEY_free(pkey);
	}

	bool SetFromEc(EC_KEY* ec)
	{
		EVP_PKEY_free(pkey);
		pkey = EvpFromEc(ec);
		if (!pkey || !EcPublicUncompressed(ec, public_uncompressed))
			return false;
		public_b64url = B64Encode(public_uncompressed, B64URL, false);
		return true;
	}
};

inline bool GenerateVapid(VapidKeys& keys)
{
	EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ec || EC_KEY_generate_key(ec) != 1)
	{
		EC_KEY_free(ec);
		return false;
	}
	bool ok = keys.SetFromEc(ec);
	EC_KEY_free(ec);
	return ok;
}

inline bool SaveVapidPem(const VapidKeys& keys, const std::string& path)
{
	if (!keys.pkey)
		return false;
	BIO* bio = BIO_new_file(path.c_str(), "w");
	if (!bio)
		return false;
	bool ok = PEM_write_bio_PrivateKey(bio, keys.pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
	BIO_free(bio);
	return ok;
}

inline bool LoadVapidPem(VapidKeys& keys, const std::string& path)
{
	BIO* bio = BIO_new_file(path.c_str(), "r");
	if (!bio)
		return false;
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!pkey)
		return false;
	EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
	EVP_PKEY_free(pkey);
	if (!ec)
		return false;
	bool ok = keys.SetFromEc(ec);
	EC_KEY_free(ec);
	return ok;
}

inline bool IsInternalSockaddr(const sockaddr* sa, socklen_t len)
{
	if (!sa)
		return true;
	if (sa->sa_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in)))
	{
		const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
		uint32_t a = ntohl(in->sin_addr.s_addr);
		if ((a & 0xFF000000u) == 0x7F000000u) // 127.0.0.0/8
			return true;
		if ((a & 0xFF000000u) == 0x0A000000u) // 10.0.0.0/8
			return true;
		if ((a & 0xFFF00000u) == 0xAC100000u) // 172.16.0.0/12
			return true;
		if ((a & 0xFFFF0000u) == 0xC0A80000u) // 192.168.0.0/16
			return true;
		if ((a & 0xFFFF0000u) == 0xA9FE0000u) // 169.254.0.0/16
			return true;
		if ((a & 0xFFC00000u) == 0x64400000u) // 100.64.0.0/10
			return true;
		if ((a & 0xFF000000u) == 0x00000000u) // 0.0.0.0/8
			return true;
		if ((a & 0xF0000000u) == 0xE0000000u) // multicast
			return true;
		return false;
	}
	if (sa->sa_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6)))
	{
		const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
		const unsigned char* p = in6->sin6_addr.s6_addr;
		// v4-mapped
		const unsigned char mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
		if (memcmp(p, mapped, 12) == 0)
		{
			sockaddr_in v4{};
			v4.sin_family = AF_INET;
			memcpy(&v4.sin_addr, p + 12, 4);
			return IsInternalSockaddr(reinterpret_cast<sockaddr*>(&v4), sizeof(v4));
		}
		// ::1
		static const unsigned char loop[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
		if (memcmp(p, loop, 16) == 0)
			return true;
		// ::
		static const unsigned char any[16] = { 0 };
		if (memcmp(p, any, 16) == 0)
			return true;
		// fc00::/7 unique local
		if ((p[0] & 0xfe) == 0xfc)
			return true;
		// fe80::/10 link-local
		if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
			return true;
		// multicast ff00::/8
		if (p[0] == 0xff)
			return true;
		return false;
	}
	return true;
}

inline bool ParseHttpsUrl(const std::string& url, std::string& host, std::string& port, std::string& path)
{
	if (url.size() < 9 || url.compare(0, 8, "https://") != 0)
		return false;
	if (url.size() > 2048)
		return false;
	size_t start = 8;
	if (url.find('@', start) != std::string::npos)
	{
		size_t at = url.find('@', start);
		size_t slash = url.find('/', start);
		if (slash == std::string::npos || at < slash)
			return false; // userinfo not allowed
	}
	std::string hostport;
	if (url[start] == '[')
	{
		size_t rb = url.find(']', start);
		if (rb == std::string::npos)
			return false;
		host = url.substr(start + 1, rb - start - 1);
		size_t cur = rb + 1;
		if (cur < url.size() && url[cur] == ':')
		{
			size_t pe = url.find_first_of("/?#", cur + 1);
			port = url.substr(cur + 1, pe == std::string::npos ? std::string::npos : pe - cur - 1);
			cur = (pe == std::string::npos) ? url.size() : pe;
		}
		else
			port = "443";
		path = (cur < url.size()) ? url.substr(cur) : "/";
	}
	else
	{
		size_t end = url.find_first_of("/?#", start);
		hostport = url.substr(start, end == std::string::npos ? std::string::npos : end - start);
		size_t colon = hostport.rfind(':');
		if (colon != std::string::npos)
		{
			host = hostport.substr(0, colon);
			port = hostport.substr(colon + 1);
		}
		else
		{
			host = hostport;
			port = "443";
		}
		path = (end == std::string::npos) ? "/" : url.substr(end);
	}
	if (host.empty() || path.empty() || path[0] != '/')
	{
		if (path.empty())
			path = "/";
	}
	if (host.empty() || port.empty())
		return false;
	for (char c : port)
	{
		if (c < '0' || c > '9')
			return false;
	}
	int p = atoi(port.c_str());
	if (p <= 0 || p > 65535)
		return false;
	if (path.find(' ') != std::string::npos)
		return false;
	return true;
}

inline bool HostIsInternalLiteral(const std::string& host)
{
	sockaddr_in in{};
	in.sin_family = AF_INET;
	if (inet_pton(AF_INET, host.c_str(), &in.sin_addr) == 1)
		return IsInternalSockaddr(reinterpret_cast<sockaddr*>(&in), sizeof(in));

	sockaddr_in6 in6{};
	in6.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, host.c_str(), &in6.sin6_addr) == 1)
		return IsInternalSockaddr(reinterpret_cast<sockaddr*>(&in6), sizeof(in6));
	return false;
}

enum class HttpStatusKind
{
	Ok,
	Gone,
	Error
};

struct HttpResult
{
	HttpStatusKind kind = HttpStatusKind::Error;
	int status = 0;
	std::string error;
};

#ifndef _WIN32
inline void CloseFd(int fd)
{
	if (fd >= 0)
		close(fd);
}
#else
inline void CloseFd(int fd)
{
	if (fd >= 0)
		closesocket(static_cast<SOCKET>(fd));
}
#endif

inline HttpResult HttpsPost(const std::string& url, const std::string& body,
	const std::vector<std::pair<std::string, std::string>>& headers, int timeout_sec)
{
	HttpResult r;
	std::string host, port, path;
	if (!ParseHttpsUrl(url, host, port, path))
	{
		r.error = "invalid https url";
		return r;
	}

	addrinfo hints{};
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	addrinfo* res = nullptr;
	int gerr = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
	if (gerr != 0 || !res)
	{
		r.error = "dns failed";
		return r;
	}

	int fd = -1;
	for (addrinfo* ai = res; ai; ai = ai->ai_next)
	{
		if (IsInternalSockaddr(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)))
			continue;
		int s = static_cast<int>(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
		if (s < 0)
			continue;
		timeval tv{};
		tv.tv_sec = timeout_sec;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
		if (connect(s, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0)
		{
			fd = s;
			break;
		}
		CloseFd(s);
	}
	freeaddrinfo(res);
	if (fd < 0)
	{
		r.error = "connect failed (blocked internal or unreachable)";
		return r;
	}

	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx)
	{
		CloseFd(fd);
		r.error = "ssl ctx";
		return r;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
	SSL_CTX_set_default_verify_paths(ctx);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	SSL* ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_tlsext_host_name(ssl, host.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_set1_host(ssl, host.c_str());
#endif
	if (SSL_connect(ssl) != 1)
	{
		r.error = std::string("tls handshake: ") + OpenSSLError();
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		CloseFd(fd);
		return r;
	}

	std::string req;
	req += "POST " + path + " HTTP/1.1\r\n";
	req += "Host: " + host;
	if (port != "443")
		req += ":" + port;
	req += "\r\n";
	req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	req += "Connection: close\r\n";
	for (const auto& h : headers)
		req += h.first + ": " + h.second + "\r\n";
	req += "\r\n";
	req.append(body);

	size_t off = 0;
	while (off < req.size())
	{
		int n = SSL_write(ssl, req.data() + off, static_cast<int>(req.size() - off));
		if (n <= 0)
		{
			r.error = "write failed";
			SSL_shutdown(ssl);
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			CloseFd(fd);
			return r;
		}
		off += static_cast<size_t>(n);
	}

	std::string resp;
	char buf[2048];
	for (;;)
	{
		int n = SSL_read(ssl, buf, sizeof(buf));
		if (n <= 0)
			break;
		resp.append(buf, static_cast<size_t>(n));
		if (resp.size() > 8192)
			break;
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	CloseFd(fd);

	if (resp.compare(0, 5, "HTTP/") != 0)
	{
		r.error = "bad http response";
		return r;
	}
	size_t sp = resp.find(' ');
	if (sp == std::string::npos)
	{
		r.error = "bad status line";
		return r;
	}
	r.status = atoi(resp.c_str() + sp + 1);
	if (r.status == 404 || r.status == 410)
		r.kind = HttpStatusKind::Gone;
	else if (r.status >= 200 && r.status < 300)
		r.kind = HttpStatusKind::Ok;
	else
	{
		r.kind = HttpStatusKind::Error;
		r.error = "http " + std::to_string(r.status);
	}
	return r;
}

inline HttpResult SendPush(const std::string& endpoint, const std::string& ua_public,
	const std::string& auth_secret, const std::string& plaintext, VapidKeys& vapid,
	const std::string& contact, int ttl, const std::string& urgency, int timeout_sec)
{
	HttpResult r;
	std::string origin = OriginOf(endpoint);
	if (origin.empty())
	{
		r.error = "invalid endpoint origin";
		return r;
	}
	std::string body;
	if (!EncryptAes128Gcm(plaintext, ua_public, auth_secret, body))
	{
		r.error = "encrypt failed";
		return r;
	}
	std::string jwt;
	if (!JwtEs256(vapid.pkey, origin, contact, time(nullptr) + 12 * 3600, jwt))
	{
		r.error = "vapid jwt failed";
		return r;
	}
	std::vector<std::pair<std::string, std::string>> hdrs;
	hdrs.emplace_back("Content-Type", "application/octet-stream");
	hdrs.emplace_back("Content-Encoding", "aes128gcm");
	hdrs.emplace_back("TTL", std::to_string(ttl));
	if (!urgency.empty())
		hdrs.emplace_back("Urgency", urgency);
	hdrs.emplace_back("Authorization", "vapid t=" + jwt + ", k=" + vapid.public_b64url);
	return HttpsPost(endpoint, body, hdrs, timeout_sec);
}

} // namespace WebPush
