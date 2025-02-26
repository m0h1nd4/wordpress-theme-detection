#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WordPress Theme Detector
A modular OOP implementation to detect and analyze WordPress themes from websites.
"""

import re
import logging
import time
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WordPressThemeDetector")


@dataclass
class ThemeInfo:
    """Data class to store WordPress theme information"""
    name: str
    url: Optional[str] = None
    metadata: Dict[str, str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def __str__(self) -> str:
        """Return a human-readable representation of the theme info"""
        result = [f"Theme: {self.name}"]
        if self.metadata:
            for key, value in self.metadata.items():
                result.append(f"{key}: {value}")
        return "\n".join(result)


class HttpClient:
    """Handles HTTP requests with proper error handling, timeouts, and retry mechanisms"""

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.7",
    }

    def __init__(self, timeout: int = 10, max_retries: int = 3, retry_delay: float = 1.0):
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)

    def get(self, url: str, custom_headers: Dict = None) -> requests.Response:
        """
        Send a GET request with proper error handling and retries.

        Args:
            url: The URL to request.
            custom_headers: Optional additional headers to send.

        Returns:
            Response object if successful.

        Raises:
            requests.exceptions.RequestException: On request failure after all retries.
        """
        headers = self.DEFAULT_HEADERS.copy()
        if custom_headers:
            headers.update(custom_headers)

        attempt = 0
        while attempt < self.max_retries:
            try:
                response = self.session.get(url, timeout=self.timeout, headers=headers)
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                attempt += 1
                logger.error(f"Attempt {attempt} failed for {url}: {str(e)}")
                if attempt >= self.max_retries:
                    logger.error(f"All {self.max_retries} attempts failed for {url}.")
                    raise
                time.sleep(self.retry_delay)


class WordPressThemeDetector:
    """Detects and analyzes WordPress themes from websites"""

    # Regex pattern for theme detection (case-insensitive)
    THEME_PATH_PATTERN = re.compile(r"wp-content/themes/([^/]+)/", re.IGNORECASE)

    # Metadata fields to extract from style.css
    META_FIELDS = [
        "Theme Name", "Theme URI", "Author", "Author URI",
        "Description", "Version", "License", "License URI"
    ]

    def __init__(self):
        self.http_client = HttpClient()

    def normalize_url(self, url: str) -> str:
        """
        Normalize URL by ensuring it has a scheme, lowercasing the host,
        and removing trailing slashes from the path.
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            # If no scheme, assume https
            parsed = urlparse("https://" + url)
        # Lowercase the network location and remove trailing slash from path
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/')
        normalized = parsed._replace(scheme=parsed.scheme, netloc=netloc, path=path)
        return urlunparse(normalized)

    def extract_metadata_from_css(self, css_content: str) -> Dict[str, str]:
        """
        Extract theme metadata from style.css content.

        Args:
            css_content: Content of the style.css file.

        Returns:
            Dictionary containing metadata fields.
        """
        metadata = {}
        lines = []

        # Check if the CSS content starts with a comment block (common in WordPress themes)
        css_content = css_content.strip()
        if css_content.startswith("/*"):
            # Extract comment block until closing */
            end_index = css_content.find("*/")
            if end_index != -1:
                comment_block = css_content[2:end_index]
                lines = comment_block.splitlines()
        else:
            # Fallback: use first 30 lines of the file
            lines = css_content.splitlines()[:30]

        # Search each line for metadata fields (case-insensitive matching)
        for line in lines:
            for field in self.META_FIELDS:
                # Using re.IGNORECASE and re.escape for flexibility
                match = re.search(fr"{re.escape(field)}:\s*(.+)$", line, re.IGNORECASE)
                if match:
                    metadata[field] = match.group(1).strip()
        return metadata

    def find_theme_from_html(self, html_content: str) -> Optional[str]:
        """
        Find theme name from HTML content.

        Args:
            html_content: HTML content of the webpage.

        Returns:
            Theme name if found, None otherwise.
        """
        match = self.THEME_PATH_PATTERN.search(html_content)
        if match:
            return match.group(1)
        return None

    def get_theme_details(self, base_url: str, theme_name: str) -> Optional[Dict[str, str]]:
        """
        Get theme details by downloading and parsing style.css.

        Args:
            base_url: Base website URL.
            theme_name: Name of the theme.

        Returns:
            Dictionary with theme metadata if found, None otherwise.
        """
        theme_css_url = f"{base_url}/wp-content/themes/{theme_name}/style.css"
        try:
            response = self.http_client.get(theme_css_url)
            return self.extract_metadata_from_css(response.text)
        except requests.exceptions.RequestException:
            logger.warning(f"Could not retrieve style.css for theme {theme_name}")
            return None

    def is_wordpress_site(self, html_content: str) -> bool:
        """
        Determine if a site is running WordPress.

        Args:
            html_content: HTML content of the webpage.

        Returns:
            Boolean indicating if the site is a WordPress site.
        """
        wp_indicators = [
            "wp-content",
            "wp-includes",
            'name="generator" content="WordPress',
            "/wp-admin/",
            "wp-json",
        ]
        return any(indicator in html_content for indicator in wp_indicators)

    def detect_theme(self, url: str) -> Tuple[bool, Optional[ThemeInfo]]:
        """
        Detect WordPress theme from a given URL.

        Args:
            url: URL of the website to check.

        Returns:
            Tuple containing:
                - Boolean indicating if the site is WordPress.
                - ThemeInfo object if a theme was detected, None otherwise.
        """
        url = self.normalize_url(url)
        try:
            response = self.http_client.get(url)
            html_content = response.text

            # Check if it's a WordPress site
            is_wp = self.is_wordpress_site(html_content)
            if not is_wp:
                return False, None

            # Find theme name
            theme_name = self.find_theme_from_html(html_content)
            if not theme_name:
                return True, None

            # Get theme details
            metadata = self.get_theme_details(url, theme_name)
            return True, ThemeInfo(
                name=theme_name,
                url=f"{url}/wp-content/themes/{theme_name}/",
                metadata=metadata
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Error detecting theme for {url}: {str(e)}")
            raise


def main(url: str) -> str:
    """
    Main function to detect WordPress theme.

    Args:
        url: URL to analyze.

    Returns:
        Human-readable result string.
    """
    detector = WordPressThemeDetector()
    try:
        is_wp, theme_info = detector.detect_theme(url)
        if not is_wp:
            return "The website does not appear to be running WordPress."
        if not theme_info:
            return "WordPress detected, but no theme could be identified."
        return str(theme_info)
    except requests.exceptions.RequestException as e:
        return f"Connection error: {str(e)}"
    except Exception as e:
        logger.exception("Unexpected error")
        return f"Unexpected error: {str(e)}"


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Please enter the URL: ")
    result = main(url)
    print(result)
