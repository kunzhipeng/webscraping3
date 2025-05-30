# coding: utf-8
__doc__ = 'Helper methods to download and crawl web content using threads'

import os
import re
import collections 
import random
import time
import datetime
import socket
import threading
import requests
import curl_cffi
import hashlib
from urllib import parse as urlparse
from . import adt
from . import alg
from . import common
from . import settings
from . import pdict

SLEEP_TIME = 0.1 # how long to sleep when waiting for network activity
DEFAULT_PRIORITY = 1 # default queue priority


class Download:
    """
    cache:
        a pdict object to use for the cache
    cache_file:
        filename to store cached data
    read_cache:
        whether to read from the cache
    write_cache:
        whether to write to the cache
    use_network:
        whether to download content not in the cache
    user_agent
        the User Agent to download content with
    timeout:
        the maximum amount of time to wait for http response
        also you can pass a tuple as (connect timeout, read timeout)
    delay:
        the minimum amount of time (in seconds) to wait after downloading content from a domain per proxy
    proxy_file:
        a filename to read proxies from
    proxy_get_fun:
        a method to fetch a proxy dynamically
    proxies:
        a list of proxies to cycle through when downloading content
    proxy:
        a proxy to be used for downloading
    headers:
        the headers to include in the request
    data:
        what to post at the URL
        if None (default) then a GET request will be made
    num_retries:
        how many times to try downloading a URL when get an error
    num_redirects:
        how many times the URL is allowed to be redirected, to avoid infinite loop
    num_caches:
        how many cache database(SQLite) files to be used
    max_size:
        maximum number of bytes that will be downloaded, or None to disable
    default:
        what to return when no content can be downloaded
    unicode:
        if True will return unicode data, if False will return binary data
    pattern:
        a regular expression or function for checking the downloaded HTML whether valid or not
    acceptable_errors:
        a list contains all acceptable HTTP codes, don't try downloading for them e.g. no need to retry for 404 error
    keep_ip_ua:
        If it's True, one proxy IP will keep using the same User-agent, otherwise will use a random User-agent for each request.
    logger:
        Specify a logger instance.
    impersonate:
        whether to use curl_cffi to download content.
    keep_session:
        whether to use the same session(cookies manager)
    """

    def __init__(self, cache=None, cache_file=None, read_cache=True, write_cache=True, use_network=True, 
            user_agent=None, timeout=30, delay=5, proxy=None, proxies=None, proxy_file=None, proxy_get_fun=None,
            headers=None, data=None, num_retries=0, num_redirects=0, num_caches=1, max_size=None, 
            default='', unicode=False, pattern=None, acceptable_errors=None, keep_ip_ua=True, logger=None, 
            impersonate=None, keep_session=False, **kwargs):
        if isinstance(timeout, tuple):
            connect_timeout, read_timeout = timeout
        else:
            connect_timeout = read_timeout = timeout
        socket.setdefaulttimeout(read_timeout)
        self.logger = logger or common.logger
        need_cache = read_cache or write_cache
        if pdict and need_cache:
            cache_file = cache_file or settings.cache_file
            self.cache = cache or pdict.PersistentDict(cache_file, num_caches=num_caches)
        else:
            self.cache = None
            if need_cache:
                self.logger.warning('Cache disabled because could not import pdict')
        # Requests session
        self.session = None
        self.settings = adt.Bag(
            read_cache = read_cache,
            write_cache = write_cache,
            use_network = use_network,
            delay = delay,
            proxies = (common.read_list(proxy_file) if proxy_file else []) or proxies or ([proxy] if proxy else []),
            proxy_file = proxy_file,
            proxy_get_fun = proxy_get_fun,
            user_agent = user_agent,
            headers = headers,
            data = data,
            num_retries = num_retries,
            num_redirects = num_redirects,
            num_caches=num_caches,
            max_size = max_size,
            default = default,
            unicode = unicode,
            pattern = pattern,
            keep_ip_ua = keep_ip_ua,
            acceptable_errors = acceptable_errors,
            impersonate = impersonate,
            keep_session=keep_session,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout
        )
        self.last_load_time = self.last_mtime = time.time()

    def get(self, url, **kwargs):
        """Download this URL and return the HTML. 
        By default HTML is cached so only have to download once.

        url:
            what to download
        kwargs:
            override any of the arguments passed to constructor
        """
        self.reload_proxies()
        self.proxy = None # the current proxy
        self.final_url = None # for tracking redirects
        self.response_code = '' # keep response code
        self.response_headers = {} # keep response headers
        self.downloading_error = None # keep downloading error
        self.error_content = None # keep error content
        self.invalid_content = None # keep invalid content
                
        # update settings with any local overrides
        settings = adt.Bag(self.settings)
        settings.update(kwargs)
        if 'timeout' in kwargs:
            timeout = kwargs['timeout']
            if isinstance(timeout, tuple):
                settings.connect_timeout, settings.read_timeout = timeout
            else:
                settings.connect_timeout = settings.read_timeout = timeout        
        # check cache for whether this content is already downloaded
        key = self.get_key(url, settings.data)
        if self.cache and settings.read_cache:
            try:
                html = self.cache[key]
                if not self.valid_response(html, settings.pattern):
                    self.invalid_content = html
                    # invalid result from download
                    html = None
            except KeyError:
                pass # have not downloaded yet
            else:
                if not html and settings.num_retries >= 0:
                    # try downloading again
                    self.logger.debug('Redownloading')
                    settings.num_retries -= 1
                else:
                    # return previously downloaded content
                    return html or settings.default 
        if not settings.use_network:
            # only want previously cached content
            return settings.default 

        html = None
        # attempt downloading content at URL
        while settings.num_retries >= 0 and html is None:
            settings.num_retries -= 1
            if 'proxy' in settings:
                # 'proxy' argument has highest priority
                self.proxy = settings.proxy
            elif settings.proxy_get_fun:
                # fetch a proxy via proxy_get_fun
                self.proxy = settings.proxy_get_fun()
            else:
                self.proxy = self.get_proxy(settings.proxies)
            # crawl slowly for each domain to reduce risk of being blocked
            self.throttle(url, headers=settings.headers, delay=settings.delay, proxy=self.proxy) 
            html = self.fetch(url, headers=settings.headers, data=settings.data, proxy=self.proxy, user_agent=settings.user_agent, pattern=settings.pattern, impersonate=settings.impersonate,
                              keep_session=settings.keep_session, connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout, acceptable_errors=settings.acceptable_errors, unicode=settings.unicode)

        if html:
            if settings.num_redirects > 0:
                # allowed to redirect
                redirect_url = get_redirect(url=url, html=html)
                if redirect_url:
                    # found a redirection
                    self.logger.debug('%s redirecting to %s' % (url, redirect_url))
                    settings.num_redirects -= 1
                    html = self.get(redirect_url, **settings) or ''
                    # make relative links absolute so will still work after redirect
                    relative_re = re.compile('(<\s*a[^>]+href\s*=\s*["\']?)(?!http)([^"\'>]+)', re.IGNORECASE)
                    try:
                        html = relative_re.sub(lambda m: m.group(1) + urlparse.urljoin(url, m.group(2)), html)
                    except UnicodeDecodeError:
                        pass
            html = self._clean_content(html=html, max_size=settings.max_size)

        if self.cache and settings.write_cache:
            # cache results
            self.cache[key] = html
            if url != self.final_url:
                # cache what URL was redirected to
                self.cache.meta(key, dict(url=self.final_url))
        
        # return default if no content
        return html or settings.default 

    def get_key(self, url, data=None):
        """Create key for caching this request
        """
        key = url
        if data:
            key += ' ' + str(data)
        return key


    def _clean_content(self, html, max_size):
        """Clean up downloaded content

        html:
            the input to clean
        max_size:
            the maximum size of data allowed
        """
        if max_size is not None and len(html) > max_size:
            self.logger.info('Webpage is too big: %s' % len(html))
            html = '' # too big to store
        return html


    def get_proxy(self, proxies=None):
        """Return random proxy if available
        """
        if proxies:
            proxy = random.choice(proxies)
        elif self.settings.proxies:
            # select next available proxy
            proxy = random.choice(self.settings.proxies)
        else:
            proxy = None
        return proxy


    # cache the user agent used for each proxy
    proxy_agents = {}
    def get_user_agent(self, proxy, headers=None):
        """Get user agent for this proxy
        """
        if headers:
            for k, v in headers.items():
                if str(k).lower() == 'user-agent':
                    return v

        if self.settings.keep_ip_ua and proxy in Download.proxy_agents:
            # have used this proxy before so return same user agent
            user_agent = Download.proxy_agents[proxy]
        else:
            # assign random user agent to this proxy
            user_agent = alg.rand_agent()
            Download.proxy_agents[proxy] = user_agent
        return user_agent


    def valid_response(self, html, pattern):
        """Return whether the response matches the pattern
        """
        if html is None:
            return False
        if not pattern:
            return True
        elif callable(pattern):
            # Is a function
            return pattern(html)
        else:
            return re.compile(pattern, re.DOTALL|re.IGNORECASE).search(html)


    def fetch(self, url, headers=None, data=None, proxy=None, user_agent=None, pattern=None, impersonate=None, keep_session=False, connect_timeout=30, read_timeout=30, acceptable_errors=None, unicode=False):
        """Simply download the url and return the content
        """
        if not keep_session or self.session == None:
            if impersonate:
                self.session = curl_cffi.Session(impersonate=impersonate)
            else:
                self.session = requests.Session()
            
        headers = headers or {}
        headers['User-Agent'] = user_agent or self.get_user_agent(proxy, headers)  
        for name, value in settings.default_headers.items():
            if name not in headers:
                if name == 'Referer':
                    value = url
                headers[name] = value            
        
        proxies = None
        if proxy:
            if '://' not in proxy:
                _proxy = 'http://' + proxy
            else:
                _proxy = proxy
            proxies = {'http': _proxy, 'https': _proxy}

        self.logger.info('Downloading %s %s' % (url, data or ''))
        try:
            resp = None
            if data is None:
                # Get method
                resp = self.session.get(url, headers=headers, proxies=proxies, timeout=(connect_timeout, read_timeout))
            else:
                # Post method
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                resp = self.session.post(url, data=data, headers=headers, proxies=proxies, timeout=(connect_timeout, read_timeout))             
            if resp.status_code >= 400:
                # HTTP ERROR
                raise Exception('HTTP Error {}: {}'.format(resp.status_code, resp.reason))
        except Exception as e:
            if isinstance(e, requests.exceptions.ConnectTimeout):
                error = '<Connect timeout error>'
            elif isinstance(e, requests.exceptions.ConnectionError):
                error = '<Connection error>'
            elif isinstance(e, requests.exceptions.ReadTimeout):
                error = '<Read timeout>'
            elif isinstance(e, requests.exceptions.InvalidHeader):
                error = '<Invalid request header>'
            else:
                error = str(e)
            self.downloading_error = error
            if not resp is None:
                self.response_code = str(resp.status_code)
                self.error_content = resp.text if unicode else resp.content
            self.logger.warning('Download error with requests: %s %s %s' % (url, error, proxy))
            if acceptable_errors and self.response_code in acceptable_errors:
                content, self.final_url = self.settings.default, url
            else:
                content, self.final_url = None, url
        else:
            self.response_code = str(resp.status_code)  
            content = resp.text if unicode else resp.content
            self.response_headers = resp.headers
            if resp.history:
                self.final_url = resp.history[-1].headers.get('Location', resp.history[-1].url)
            else:
                self.final_url = resp.url
            if pattern and not self.valid_response(content, pattern):
                # invalid result from download
                self.invalid_content = content
                content = None
                self.logger.warning('Content did not match expected pattern: %s, %s' % (url, proxy))
        return content


    _domains = adt.HashDict()
    def throttle(self, url, headers, delay, proxy=None, variance=0.5):
        """Delay a minimum time for each domain per proxy by storing last access time

        url
            what intend to download
        delay
            the minimum amount of time (in seconds) to wait after downloading content from this domain
        headers
            what headers to be sent
        proxy
            the proxy to download through
        variance
            the amount of randomness in delay, 0-1
        """
        if delay > 0:
            # Use a random delay value
            delay = delay * (1 + variance * (random.random() - 0.5))
            # To throttle by proxy
            key = str(proxy) + ':' + common.get_domain(url)
            self.__do_throttle(key, delay)
          
                
    def __do_throttle(self, key, delay):
        """Delay for key specified
        """
        if key in Download._domains:
            while datetime.datetime.now() < Download._domains.get(key):
                time.sleep(SLEEP_TIME)
        # update domain timestamp to when can query next
        Download._domains[key] = datetime.datetime.now() + datetime.timedelta(seconds=delay)


    def reload_proxies(self, timeout=600):
        """Check periodically for updated proxy file

        timeout:
            the number of seconds before check for updated proxies
        """
        if self.settings.proxy_file and time.time() - self.last_load_time > timeout:
            self.last_load_time = time.time()
            if os.path.exists(self.settings.proxy_file):
                if os.stat(self.settings.proxy_file).st_mtime != self.last_mtime:
                    self.last_mtime = os.stat(self.settings.proxy_file).st_mtime
                    self.settings.proxies = common.read_list(self.settings.proxy_file)
                    self.logger.debug('Reloaded proxies from updated file.')

        
    def save_as(self, url, filename=None, save_dir='attachments', **kwargs):
        """Download url and save to disk

        url:
            the webpage to download
        filename:
            Output file to save to. If not set then will save to file based on URL
        """
        save_path = os.path.join(save_dir, filename or '%s.%s' % (hashlib.md5(url).hexdigest(), common.get_extension(url)))
        file_bytes = self.get(url, **kwargs)
        if file_bytes:
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)
            with open(save_path, 'wb') as f:
                f.write(file_bytes)
            return save_path
        else:
            return None
        


def get_redirect(url, html):
    """Check for meta redirects and return redirect URL if found
    """
    match = re.compile('<meta[^>]*?url=(.*?)["\']', re.IGNORECASE).search(html)
    if match:
        return urlparse.urljoin(url, common.unescape(match.groups()[0].strip())) 


class StopCrawl(Exception):
    """Raise this exception to interrupt crawl
    """
    pass


def threaded_get(url=None, urls=None, url_iter=None, num_threads=10, dl=None, cb=None, depth=True, **kwargs):
    """Download these urls in parallel

    url:
        the webpage to download
    urls:
        the webpages to download
    num_threads:
        the number of threads to download urls with
    cb:
        Called after each download with the HTML of the download. 
        The arguments are the url and downloaded html.
        Whatever URLs are returned are added to the crawl queue.
    dl:
        A callback for customizing the download.
        Takes the download object and url and should return the HTML.
    depth:
        True for depth first search
    """
    running = True
    lock = threading.Lock()
    def add_iter_urls():
        if lock.acquire(False):
            for url in url_iter or []:
                download_queue.append(url)
                break
            lock.release()


    def process_queue():
        """Thread for downloading webpages
        """
        D = Download(**kwargs)

        while True:
            try:
                url = download_queue.pop() if depth else download_queue.popleft()
            except IndexError:
                add_iter_urls()
                break
            else:
                # download this url
                html = dl(D, url, **kwargs) if dl else D.get(url, **kwargs)
                if cb:
                    try:
                        # use callback to process downloaded HTML
                        result = cb(D, url, html)
                    except StopCrawl:
                        common.logger.info('Stopping crawl signal')
                    except Exception:
                        # catch any callback error to avoid losing thread
                        common.logger.exception('\nIn callback for: ' + str(url))
                    else:
                        # add these URL's to crawl queue
                        for link in result or []:
                            download_queue.append(urlparse.urljoin(url, link))
                                        
    download_queue = collections.deque()
    if urls:
        download_queue.extend(urls)
    if url:
        download_queue.append(url)
    common.logger.debug('Start new crawl')

    # wait for all download threads to finish
    threads = []
    while running and (threads or download_queue):
        for thread in threads:
            if not thread.is_alive():
                threads.remove(thread)
        while len(threads) < num_threads and download_queue:
            # cat start more threads
            thread = threading.Thread(target=process_queue)
            thread.setDaemon(True) # set daemon so main thread can exit when receives ctrl-c
            thread.start()
            threads.append(thread)
        time.sleep(SLEEP_TIME)