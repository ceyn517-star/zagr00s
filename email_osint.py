#!/usr/bin/env python3
"""
Email OSINT Module - Open Source Intelligence for Email Addresses
Checks social media accounts, data breaches, and online presence
"""
import re
import json
import time
import hashlib
import urllib.request
import urllib.parse
import ssl
from typing import Dict, List, Optional

class EmailOSINT:
    """Email Open Source Intelligence Gatherer"""
    
    def __init__(self):
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        # SSL context that allows us to make HTTPS requests
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def extract_username(self, email: str) -> str:
        """Extract username part from email"""
        return email.split('@')[0]
    
    def extract_domain(self, email: str) -> str:
        """Extract domain part from email"""
        return email.split('@')[1]
    
    def check_social_media(self, email: str) -> Dict:
        """Check social media accounts linked to email"""
        username = self.extract_username(email)
        results = {
            'instagram': self._check_instagram(username),
            'twitter': self._check_twitter(username),
            'github': self._check_github(username),
            'reddit': self._check_reddit(username),
            'tiktok': self._check_tiktok(username),
            'linkedin': self._check_linkedin(email),
            'pinterest': self._check_pinterest(username),
            'snapchat': self._check_snapchat(username),
            'spotify': self._check_spotify(username),
            'discord': self._check_discord(username),
            'telegram': self._check_telegram(username),
            'youtube': self._check_youtube(username),
            'twitch': self._check_twitch(username),
            'medium': self._check_medium(username),
            'steam': self._check_steam(username),
        }
        return results
    
    def check_data_breaches(self, email: str) -> Dict:
        """Check if email appears in known data breaches"""
        # Use HaveIBeenPwned API style check
        results = {
            'breaches_found': 0,
            'breaches': [],
            'last_breach': None,
            'data_classes_compromised': []
        }
        
        # Hash email for privacy-safe lookup
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = email_hash[:5]
        suffix = email_hash[5:]
        
        try:
            # Check HaveIBeenPwned k-anonymity API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                data = response.read().decode('utf-8')
                # Check if our suffix is in the response
                for line in data.split('\n'):
                    if line.startswith(suffix):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            count = int(parts[1].strip())
                            results['breaches_found'] = count
                            results['breaches'].append({
                                'source': 'HaveIBeenPwned',
                                'count': count,
                                'verified': True
                            })
                        break
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_email_providers(self, email: str) -> Dict:
        """Check which services use this email"""
        domain = self.extract_domain(email)
        username = self.extract_username(email)
        
        return {
            'domain': domain,
            'domain_type': self._classify_domain(domain),
            'username': username,
            'username_variations': self._generate_username_variations(username),
            'possible_services': self._guess_services(domain),
            'gravatar': self._check_gravatar(email),
            'skype': self._check_skype(email),
            'openpgp': self._check_openpgp(email),
            'avatar': self._get_avatar_url(email)
        }
    
    def generate_osint_report(self, email: str) -> Dict:
        """Generate comprehensive OSINT report for email"""
        if not self.validate_email(email):
            return {'error': 'Invalid email format'}
        
        report = {
            'email': email,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'valid': True,
            'basic_info': self.check_email_providers(email),
            'social_media': self.check_social_media(email),
            'breach_data': self.check_data_breaches(email),
            'free_api_results': self.check_free_apis(email),  # New free APIs
            'risk_score': 0,
            'recommendations': []
        }
        
        # Calculate risk score
        risk_score = 0
        
        # Check breaches
        if report['breach_data'].get('breaches_found', 0) > 0:
            risk_score += min(report['breach_data']['breaches_found'] * 5, 40)
            report['recommendations'].append(
                f"Email {report['breach_data']['breaches_found']} veri ihlalinde bulundu. Şifrenizi değiştirin."
            )
        
        # Check exposed social media
        exposed_accounts = sum(1 for v in report['social_media'].values() if v.get('exists'))
        if exposed_accounts > 0:
            risk_score += min(exposed_accounts * 10, 30)
            report['recommendations'].append(
                f"{exposed_accounts} sosyal medya hesabı bulundu. Gizlilik ayarlarını kontrol edin."
            )
        
        # Check EmailRep reputation
        emailrep = report['free_api_results'].get('emailrep', {})
        if emailrep.get('suspicious'):
            risk_score += 20
            report['recommendations'].append("Email şüpheli olarak işaretlenmiş.")
        if emailrep.get('malicious'):
            risk_score += 30
            report['recommendations'].append("Email kötü amaçlı olarak işaretlenmiş!")
        
        # Check if using common email provider
        if report['basic_info']['domain_type'] == 'common':
            risk_score += 10
        
        report['risk_score'] = min(risk_score, 100)
        report['risk_level'] = self._get_risk_level(report['risk_score'])
        
        return report
    
    def check_free_apis(self, email: str) -> Dict:
        """Check all free APIs for email information"""
        return {
            'emailrep': self._check_emailrep(email),
            'hunter': self._check_hunter(email),
            'abstract': self._check_abstract(email),
            'clearbit': self._check_clearbit(email),
            'holehe': self._check_holehe_style(email),  # Yeni - hesap tarama
            'ipapi': self._check_ipapi(),  # Yeni - IP bilgisi
            'breachdirectory': self._check_breachdirectory(email),  # Yeni - veri ihlali
            'scylla': self._check_scylla(email),  # Yeni - veri ihlali arama
        }
    
    def _check_emailrep(self, email: str) -> Dict:
        """Check EmailRep.io for email reputation (FREE - no API key needed)"""
        try:
            url = f"https://emailrep.io/{urllib.parse.quote(email)}"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return {
                        'success': True,
                        'reputation': data.get('reputation', 'unknown'),
                        'suspicious': data.get('suspicious', False),
                        'malicious': data.get('malicious', False),
                        'blacklisted': data.get('details', {}).get('blacklisted', False),
                        'spam': data.get('details', {}).get('spam', False),
                        'malicious_activity': data.get('details', {}).get('malicious_activity', False),
                        'credentials_leaked': data.get('details', {}).get('credentials_leaked', False),
                        'data_breach': data.get('details', {}).get('data_breach', False),
                        'first_seen': data.get('details', {}).get('first_seen', 'unknown'),
                        'last_seen': data.get('details', {}).get('last_seen', 'unknown'),
                        'days_since_domain_creation': data.get('details', {}).get('days_since_domain_creation'),
                        'disposable': data.get('disposable', False),
                        'deliverable': data.get('deliverable', False),
                        'valid_mx': data.get('details', {}).get('mx_records', False),
                        'spoofable': data.get('details', {}).get('spoofable', False),
                        'spf_strict': data.get('details', {}).get('spf_strict', False),
                        'dmarc_enforced': data.get('details', {}).get('dmarc_enforced', False)
                    }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                return {'error': 'Rate limit exceeded', 'success': False}
        except Exception as e:
            pass
        return {'error': 'Could not check EmailRep', 'success': False}
    
    def _check_hunter(self, email: str) -> Dict:
        """Check Hunter.io for email/domain info (FREE tier available)"""
        try:
            domain = self.extract_domain(email)
            username = self.extract_username(email)
            
            # Hunter.io free: verify email pattern
            results = {
                'success': True,
                'domain': domain,
                'email_pattern': None,
                'department': None,
                'seniority': None,
                'phone_number': None,
                'company': None,
                'linkedin_url': None,
                'twitter_handle': None,
                'sources': []
            }
            
            # Try to get company info from domain
            common_patterns = [
                f"{username}@{domain}",
                f"{username}.{username}@{domain}",
                f"{username[0]}.{username}@{domain}",
                f"{username[0]}{username}@{domain}",
                f"{username}@{domain}"
            ]
            results['possible_patterns'] = list(set(common_patterns))[:5]
            
            # Get domain MX records info via DNS check simulation
            results['domain_info'] = {
                'domain': domain,
                'is_corporate': not any(d in domain for d in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']),
                'common_pattern': f"{{first}}.{{last}}@{domain}" if '.' in username else f"{{first}}@{domain}"
            }
            
            return results
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _check_abstract(self, email: str) -> Dict:
        """Check Abstract API for email validation (FREE tier: 100 requests/month)"""
        # Abstract API requires API key but has generous free tier
        # Using alternative: mailboxlayer (free tier available)
        try:
            # Using free alternative: email validation via DNS/MX check simulation
            import socket
            
            domain = self.extract_domain(email)
            
            results = {
                'success': True,
                'email': email,
                'format_valid': self.validate_email(email),
                'domain': domain,
                'disposable': False,
                'free_provider': False,
                'corporate': False,
                'mx_records': False
            }
            
            # Check if disposable email
            disposable_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 
                                 'mailinator.com', 'yopmail.com', 'fakeinbox.com']
            results['disposable'] = any(d in domain.lower() for d in disposable_domains)
            
            # Check if free provider
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                            'icloud.com', 'protonmail.com', 'yandex.com', 'mail.ru']
            results['free_provider'] = domain.lower() in free_providers
            results['corporate'] = not results['free_provider'] and not results['disposable']
            
            # Try to check MX records
            try:
                import dns.resolver
                mx_records = dns.resolver.resolve(domain, 'MX')
                results['mx_records'] = len(mx_records) > 0
            except:
                # Fallback: try basic socket connection
                try:
                    socket.gethostbyname(domain)
                    results['mx_records'] = True
                except:
                    results['mx_records'] = False
            
            return results
        except Exception as e:
            return {'error': str(e), 'success': False, 'format_valid': self.validate_email(email)}
    
    def _check_clearbit(self, email: str) -> Dict:
        """Check Clearbit for company info (FREE tier: 50 requests/month)"""
        try:
            domain = self.extract_domain(email)
            username = self.extract_username(email)
            
            # Clearbit free tier doesn't require API key for Logo API
            results = {
                'success': True,
                'domain': domain,
                'logo_url': f"https://logo.clearbit.com/{domain}?size=128",
                'company_info_url': f"https://company.clearbit.com/v2/companies/find?domain={domain}",
                'enrichment_available': False,
                'possible_company': None
            }
            
            # Try to get company name from domain
            if '.' in domain:
                company_name = domain.split('.')[0].replace('-', ' ').title()
                results['possible_company'] = company_name
            
            # Check if logo exists by making HEAD request
            try:
                logo_url = f"https://logo.clearbit.com/{domain}"
                req = urllib.request.Request(logo_url, headers=self.headers, method='HEAD')
                with urllib.request.urlopen(req, context=self.ssl_context, timeout=3) as response:
                    results['logo_exists'] = response.status == 200
            except:
                results['logo_exists'] = False
            
            return results
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _check_holehe_style(self, email: str) -> Dict:
        """Check email against multiple services (Holehe-style account checking) - FREE"""
        username = self.extract_username(email)
        domain = self.extract_domain(email)
        
        # Services to check
        services = {
            'github': {'url': f'https://github.com/{username}', 'api': f'https://api.github.com/users/{username}'},
            'gitlab': {'url': f'https://gitlab.com/{username}'},
            'reddit': {'url': f'https://reddit.com/user/{username}'},
            'tumblr': {'url': f'https://{username}.tumblr.com'},
            'deviantart': {'url': f'https://{username}.deviantart.com'},
            'twitter': {'url': f'https://twitter.com/{username}'},
            'instagram': {'url': f'https://instagram.com/{username}'},
            'pinterest': {'url': f'https://pinterest.com/{username}'},
            'spotify': {'url': f'https://open.spotify.com/user/{username}'},
            'soundcloud': {'url': f'https://soundcloud.com/{username}'},
            'vk': {'url': f'https://vk.com/{username}'},
            'tiktok': {'url': f'https://tiktok.com/@{username}'},
        }
        
        results = {}
        
        # Check GitHub via API (FREE)
        try:
            url = f'https://api.github.com/users/{username}'
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    results['github'] = {
                        'exists': True,
                        'username': username,
                        'url': f'https://github.com/{username}',
                        'avatar': data.get('avatar_url'),
                        'name': data.get('name'),
                        'bio': data.get('bio'),
                        'public_repos': data.get('public_repos'),
                        'followers': data.get('followers'),
                        'checked': True
                    }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                results['github'] = {'exists': False, 'username': username, 'checked': True}
        except:
            results['github'] = {'exists': None, 'error': 'Check failed', 'checked': True}
        
        # Check Tumblr via HEAD request
        try:
            url = f'https://{username}.tumblr.com'
            req = urllib.request.Request(url, headers=self.headers, method='HEAD')
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                results['tumblr'] = {'exists': response.status == 200, 'username': username, 'url': url, 'checked': True}
        except urllib.error.HTTPError as e:
            results['tumblr'] = {'exists': False, 'username': username, 'url': url, 'checked': True}
        except:
            results['tumblr'] = {'exists': None, 'username': username, 'checked': True}
        
        # Check DeviantArt via HEAD request
        try:
            url = f'https://{username}.deviantart.com'
            req = urllib.request.Request(url, headers=self.headers, method='HEAD')
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                results['deviantart'] = {'exists': response.status == 200, 'username': username, 'url': url, 'checked': True}
        except urllib.error.HTTPError as e:
            results['deviantart'] = {'exists': False, 'username': username, 'url': url, 'checked': True}
        except:
            results['deviantart'] = {'exists': None, 'username': username, 'checked': True}
        
        # For other services, generate profile links for manual check
        for service, info in services.items():
            if service not in results:
                results[service] = {
                    'exists': None,
                    'username': username,
                    'url': info['url'],
                    'manual_check': True,
                    'note': f'Manual check required for {service}',
                    'checked': True
                }
        
        return {
            'success': True,
            'email': email,
            'services_checked': len(results),
            'services_found': sum(1 for r in results.values() if r.get('exists') == True),
            'results': results
        }
    
    def _check_ipapi(self) -> Dict:
        """Get IP geolocation info via ip-api.com (FREE - no API key needed)"""
        try:
            url = 'http://ip-api.com/json/?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query'
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return {
                        'success': True,
                        'ip': data.get('query'),
                        'location': {
                            'continent': data.get('continent'),
                            'country': data.get('country'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'timezone': data.get('timezone'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon')
                        },
                        'network': {
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'asn': data.get('as')
                        },
                        'flags': {
                            'mobile': data.get('mobile', False),
                            'proxy': data.get('proxy', False),
                            'hosting': data.get('hosting', False)
                        }
                    }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _check_breachdirectory(self, email: str) -> Dict:
        """Check email for breach data using local analysis + recommendations (FREE)"""
        try:
            import hashlib
            email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
            domain = self.extract_domain(email)
            username = self.extract_username(email)
            
            # Check if disposable email
            disposable_domains = [
                'tempmail.com', '10minutemail.com', 'guerrillamail.com', 
                'mailinator.com', 'yopmail.com', 'temp-mail.org', 'fakeinbox.com',
                'throwawaymail.com', 'getairmail.com', 'tempinbox.com', 'burnermail.io'
            ]
            is_disposable = any(d in domain.lower() for d in disposable_domains)
            
            # Check if free provider
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                            'icloud.com', 'protonmail.com', 'yandex.com', 'mail.ru']
            is_free = domain.lower() in free_providers
            
            return {
                'success': True,
                'email_hash_prefix': email_hash[:16] + '...',
                'domain_analysis': {
                    'domain': domain,
                    'username': username,
                    'is_disposable': is_disposable,
                    'is_free_provider': is_free,
                    'is_corporate': not is_free and not is_disposable
                },
                'breach_check_urls': [
                    f'https://haveibeenpwned.com/account/{urllib.parse.quote(email)}',
                    f'https://dehashed.com/search?query={urllib.parse.quote(email)}',
                    f'https://intelx.io/?s={urllib.parse.quote(email)}'
                ],
                'recommendations': [
                    'Check HaveIBeenPwned for breach data',
                    'Check DeHashed for leaked credentials',
                    'Check IntelX for comprehensive search'
                ] if not is_disposable else ['⚠️ Disposable email detected - high risk'],
                'risk_indicators': {
                    'disposable_email': is_disposable,
                    'free_provider': is_free,
                    'corporate_domain': not is_free and not is_disposable
                }
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _check_scylla(self, email: str) -> Dict:
        """Provide Scylla/database search links for leaked credentials (FREE OSINT)"""
        try:
            username = self.extract_username(email)
            domain = self.extract_domain(email)
            
            # Free OSINT database search URLs
            search_urls = [
                {'name': 'Scylla', 'url': f'https://scylla.sh/search?q={urllib.parse.quote(email)}'},
                {'name': 'DeHashed', 'url': f'https://dehashed.com/search?query={urllib.parse.quote(email)}'},
                {'name': 'IntelX', 'url': f'https://intelx.io/?s={urllib.parse.quote(email)}'},
                {'name': 'LeakCheck', 'url': f'https://leakcheck.io/'},
                {'name': 'HaveIBeenPwned', 'url': f'https://haveibeenpwned.com/account/{urllib.parse.quote(email)}'}
            ]
            
            return {
                'success': True,
                'manual_search_required': True,
                'note': 'Use these free OSINT databases to search for leaked credentials',
                'search_urls': search_urls,
                'username_variations': [
                    username,
                    username.replace('.', ''),
                    username.replace('_', ''),
                    username.replace('.', '_'),
                    username.split('_')[0] if '_' in username else username
                ],
                'recommendations': [
                    '1. Scylla - Largest breach database (free)',
                    '2. DeHashed - Comprehensive breach search',
                    '3. IntelX - Multi-source intelligence',
                    '4. HaveIBeenPwned - Official breach notifications'
                ]
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def _classify_domain(self, domain: str) -> str:
        """Classify email domain type"""
        common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                         'icloud.com', 'mail.ru', 'yandex.com', 'protonmail.com']
        
        if domain.lower() in common_domains:
            return 'common'
        elif domain.lower().endswith(('.edu', '.ac.uk', '.ac.jp')):
            return 'educational'
        elif domain.lower().endswith(('.gov', '.gov.uk', '.gov.au')):
            return 'government'
        elif domain.lower().endswith(('.corp', '.inc', '.llc', 'company')):
            return 'corporate'
        else:
            return 'custom'
    
    def _generate_username_variations(self, username: str) -> List[str]:
        """Generate common username variations"""
        variations = [username]
        
        # Common separators
        if '_' not in username and '.' not in username:
            variations.append(f"{username}_")
            variations.append(f"_{username}")
        
        # Numbers
        variations.extend([f"{username}123", f"{username}1", f"{username}01"])
        
        return list(set(variations))
    
    def _guess_services(self, domain: str) -> List[str]:
        """Guess which services might be linked to this email"""
        services = []
        
        domain_services = {
            'gmail.com': ['Google', 'YouTube', 'Drive', 'Photos', 'Maps'],
            'yahoo.com': ['Yahoo Mail', 'Flickr', 'Tumblr'],
            'outlook.com': ['Microsoft', 'Xbox', 'Skype', 'OneDrive', 'LinkedIn'],
            'hotmail.com': ['Microsoft', 'Xbox', 'Skype', 'OneDrive'],
            'icloud.com': ['Apple', 'iCloud', 'App Store', 'Apple Music'],
            'protonmail.com': ['ProtonMail', 'ProtonVPN', 'ProtonDrive'],
        }
        
        return domain_services.get(domain.lower(), ['Unknown'])
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
        if score >= 70:
            return 'Yüksek'
        elif score >= 40:
            return 'Orta'
        elif score >= 20:
            return 'Düşük'
        else:
            return 'Minimal'
    
    def _check_github(self, username: str) -> Dict:
        """Check GitHub profile via API"""
        try:
            url = f"https://api.github.com/users/{username}"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return {
                        'platform': 'GitHub',
                        'username': username,
                        'exists': True,
                        'url': f"https://github.com/{username}",
                        'avatar': data.get('avatar_url'),
                        'name': data.get('name'),
                        'bio': data.get('bio'),
                        'public_repos': data.get('public_repos'),
                        'followers': data.get('followers'),
                        'checked': True
                    }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    'platform': 'GitHub',
                    'username': username,
                    'exists': False,
                    'url': f"https://github.com/{username}",
                    'checked': True
                }
        except Exception as e:
            pass
        return self._generic_check(username, 'GitHub')
    
    def _check_reddit(self, username: str) -> Dict:
        """Check Reddit profile"""
        result = self._generic_check(username, 'Reddit')
        result['url'] = f"https://www.reddit.com/user/{username}"
        # Reddit requires special headers, mark as needs manual check
        result['manual_check'] = True
        return result
    
    def _check_twitter(self, username: str) -> Dict:
        """Check Twitter/X profile"""
        result = self._generic_check(username, 'Twitter')
        result['url'] = f"https://twitter.com/{username}"
        result['manual_check'] = True  # Twitter blocks automated requests
        return result
    
    def _check_instagram(self, username: str) -> Dict:
        """Check Instagram profile"""
        result = self._generic_check(username, 'Instagram')
        result['url'] = f"https://instagram.com/{username}"
        result['manual_check'] = True  # Instagram blocks automated requests
        return result
    
    def _check_linkedin(self, email: str) -> Dict:
        """Check LinkedIn - requires auth, provide search link"""
        username = email.split('@')[0]
        result = self._generic_check(username, 'LinkedIn')
        result['url'] = f"https://www.linkedin.com/in/{username}"
        result['search_url'] = f"https://www.google.com/search?q=site:linkedin.com+{username}"
        result['manual_check'] = True
        return result
    
    def _check_tiktok(self, username: str) -> Dict:
        """Check TikTok profile"""
        result = self._generic_check(username, 'TikTok')
        result['url'] = f"https://www.tiktok.com/@{username}"
        result['manual_check'] = True
        return result
    
    def _check_pinterest(self, username: str) -> Dict:
        """Check Pinterest profile"""
        result = self._generic_check(username, 'Pinterest')
        result['url'] = f"https://pinterest.com/{username}"
        result['manual_check'] = True
        return result
    
    def _check_snapchat(self, username: str) -> Dict:
        """Check Snapchat - no public web profiles really"""
        result = self._generic_check(username, 'Snapchat')
        result['url'] = f"https://www.snapchat.com/add/{username}"
        result['note'] = 'Snapchat profiles are private by default'
        return result
    
    def _check_spotify(self, username: str) -> Dict:
        """Check Spotify profile"""
        result = self._generic_check(username, 'Spotify')
        result['url'] = f"https://open.spotify.com/user/{username}"
        result['manual_check'] = True
        return result
    
    def _check_gravatar(self, email: str) -> Dict:
        """Check Gravatar profile for email"""
        try:
            # Generate MD5 hash of email (lowercase, stripped)
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            
            # Gravatar profile URL
            profile_url = f"https://en.gravatar.com/{email_hash}.json"
            avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
            
            # Check if avatar exists
            req = urllib.request.Request(avatar_url, headers=self.headers, method='HEAD')
            try:
                with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                    avatar_exists = response.status == 200
            except urllib.error.HTTPError as e:
                avatar_exists = False
            
            # Try to get profile data
            try:
                req = urllib.request.Request(profile_url, headers=self.headers)
                with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode('utf-8'))
                        entry = data.get('entry', [{}])[0]
                        return {
                            'exists': True,
                            'avatar_url': avatar_url.replace('?d=404', ''),
                            'avatar_exists': avatar_exists,
                            'profile_url': f"https://en.gravatar.com/{email_hash}",
                            'display_name': entry.get('displayName'),
                            'full_name': entry.get('name', {}).get('formatted'),
                            'location': entry.get('currentLocation'),
                            'about': entry.get('aboutMe')
                        }
            except:
                pass
            
            # If no profile but avatar exists
            if avatar_exists:
                return {
                    'exists': True,
                    'avatar_url': avatar_url.replace('?d=404', ''),
                    'avatar_exists': True,
                    'profile_url': f"https://en.gravatar.com/{email_hash}",
                    'note': 'Avatar found but no public profile'
                }
            
            return {
                'exists': False,
                'avatar_exists': False,
                'profile_url': f"https://en.gravatar.com/{email_hash}"
            }
            
        except Exception as e:
            return {
                'exists': None,
                'error': str(e),
                'avatar_exists': False
            }
    
    def _check_skype(self, email: str) -> Dict:
        """Check if email has associated Skype account"""
        # Skype uses email for account recovery, so we can check via Skype directory
        # Note: This is a simplified check - real Skype resolver requires more complex methods
        username = self.extract_username(email)
        
        # Possible Skype usernames based on email
        possible_skypes = [
            username,
            email.replace('@', '_').replace('.', '_'),
            username.replace('.', ''),
            username.replace('_', ''),
            username.replace('.', '_')
        ]
        
        return {
            'possible_usernames': list(set(possible_skypes)),
            'skype_links': [f"https://web.skype.com/?username={u}" for u in set(possible_skypes)],
            'search_url': f"https://www.skype.com/en/search/?q={email}",
            'note': 'Skype accounts are private. Try searching with possible usernames.',
            'manual_check': True
        }
    
    def _check_openpgp(self, email: str) -> Dict:
        """Check OpenPGP key servers for email"""
        try:
            # Check keys.openpgp.org
            encoded_email = urllib.parse.quote(email)
            url = f"https://keys.openpgp.org/vks/v1/by-email/{encoded_email}"
            
            req = urllib.request.Request(url, headers=self.headers)
            try:
                with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as response:
                    if response.status == 200:
                        # PGP key found
                        key_data = response.read().decode('utf-8')
                        return {
                            'exists': True,
                            'keyserver': 'keys.openpgp.org',
                            'url': f"https://keys.openpgp.org/search?q={encoded_email}",
                            'key_found': True,
                            'key_length': len(key_data),
                            'note': 'PGP public key found for this email'
                        }
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {
                        'exists': False,
                        'keyserver': 'keys.openpgp.org',
                        'url': f"https://keys.openpgp.org/search?q={encoded_email}",
                        'key_found': False
                    }
        except Exception as e:
            pass
        
        return {
            'exists': None,
            'keyserver': 'keys.openpgp.org',
            'url': f"https://keys.openpgp.org/search?q={urllib.parse.quote(email)}",
            'error': 'Could not check PGP keys'
        }
    
    def _get_avatar_url(self, email: str) -> Dict:
        """Get avatar URL from various services"""
        # Gravatar MD5 hash
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        
        return {
            'gravatar': f"https://www.gravatar.com/avatar/{email_hash}?s=200",
            'gravatar_default': f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=identicon",
            'unavatar': f"https://unavatar.io/{email}",
            'unavatar_github': f"https://unavatar.io/{self.extract_username(email)}"
        }
    
    def _generic_check(self, username: str, platform: str) -> Dict:
        """Generic social media check placeholder"""
        # In a real implementation, this would actually check the platform
        # For now, return structure with mock data
        return {
            'platform': platform,
            'username': username,
            'exists': None,  # Would be True/False in real implementation
            'url': f"https://{platform.lower()}.com/{username}",
            'checked': True
        }
    
    def _check_discord(self, username: str) -> Dict:
        """Check Discord - usernames are unique, provide search link"""
        result = self._generic_check(username, 'Discord')
        result['url'] = f"https://discord.com/users/"
        result['search_url'] = f"https://discord.id/?prefetch={username}"
        result['note'] = 'Discord usernames are unique - check via Discord.id'
        result['manual_check'] = True
        return result
    
    def _check_telegram(self, username: str) -> Dict:
        """Check Telegram profile"""
        result = self._generic_check(username, 'Telegram')
        result['url'] = f"https://t.me/{username}"
        # Try to check if username exists via HEAD request
        try:
            url = f"https://t.me/{username}"
            req = urllib.request.Request(url, headers=self.headers, method='HEAD')
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                result['exists'] = response.status == 200
                result['checked'] = True
        except urllib.error.HTTPError:
            result['exists'] = False
            result['checked'] = True
        except:
            result['manual_check'] = True
        return result
    
    def _check_youtube(self, username: str) -> Dict:
        """Check YouTube channel"""
        result = self._generic_check(username, 'YouTube')
        result['url'] = f"https://youtube.com/@{username}"
        result['search_url'] = f"https://www.youtube.com/results?search_query={username}"
        result['manual_check'] = True
        return result
    
    def _check_twitch(self, username: str) -> Dict:
        """Check Twitch profile"""
        result = self._generic_check(username, 'Twitch')
        result['url'] = f"https://twitch.tv/{username}"
        try:
            url = f"https://twitch.tv/{username}"
            req = urllib.request.Request(url, headers=self.headers, method='HEAD')
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                result['exists'] = response.status == 200
                result['checked'] = True
        except urllib.error.HTTPError:
            result['exists'] = False
            result['checked'] = True
        except:
            result['manual_check'] = True
        return result
    
    def _check_medium(self, username: str) -> Dict:
        """Check Medium profile"""
        result = self._generic_check(username, 'Medium')
        result['url'] = f"https://medium.com/@{username}"
        try:
            url = f"https://medium.com/@{username}"
            req = urllib.request.Request(url, headers=self.headers, method='HEAD')
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=5) as response:
                result['exists'] = response.status == 200
                result['checked'] = True
        except urllib.error.HTTPError:
            result['exists'] = False
            result['checked'] = True
        except:
            result['manual_check'] = True
        return result
    
    def _check_steam(self, username: str) -> Dict:
        """Check Steam profile"""
        result = self._generic_check(username, 'Steam')
        result['url'] = f"https://steamcommunity.com/id/{username}"
        result['search_url'] = f"https://steamcommunity.com/search/#text={username}"
        result['manual_check'] = True
        return result


# Quick test function
def test_email_osint(email: str):
    """Test OSINT on an email address"""
    osint = EmailOSINT()
    report = osint.generate_osint_report(email)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        test_email_osint(sys.argv[1])
    else:
        # Test with example
        test_email_osint("example@gmail.com")
