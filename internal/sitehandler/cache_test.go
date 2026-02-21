package sitehandler

import "testing"

func TestCacheControlForFile(t *testing.T) {
	opts := Options{}
	opts.setDefaults()

	tests := []struct {
		name string
		file string
		want string
	}{
		// html
		{"html file", "index.html", opts.HTMLCacheControl},
		{"nested html", "blog/post.html", opts.HTMLCacheControl},
		{"uppercase HTML", "PAGE.HTML", opts.HTMLCacheControl},

		// css/js
		{"css", "css/style.css", opts.AssetCacheControl},
		{"js", "js/app.js", opts.AssetCacheControl},
		{"mjs", "js/module.mjs", opts.AssetCacheControl},
		{"source map", "js/app.js.map", opts.AssetCacheControl},

		// images
		{"png", "images/logo.png", opts.AssetCacheControl},
		{"jpg", "photos/pic.jpg", opts.AssetCacheControl},
		{"jpeg", "photos/pic.jpeg", opts.AssetCacheControl},
		{"webp", "images/hero.webp", opts.AssetCacheControl},
		{"gif", "images/anim.gif", opts.AssetCacheControl},
		{"svg", "icons/arrow.svg", opts.AssetCacheControl},
		{"ico", "favicon.ico", opts.AssetCacheControl},

		// fonts
		{"woff", "fonts/body.woff", opts.AssetCacheControl},
		{"woff2", "fonts/body.woff2", opts.AssetCacheControl},
		{"ttf", "fonts/mono.ttf", opts.AssetCacheControl},
		{"eot", "fonts/legacy.eot", opts.AssetCacheControl},

		// no extension (treated as HTML)
		{"no extension", "about", opts.HTMLCacheControl},
		{"no extension nested", "blog/post", opts.HTMLCacheControl},

		// other extensions
		{"xml", "sitemap.xml", opts.OtherCacheControl},
		{"json", "manifest.json", opts.OtherCacheControl},
		{"txt", "robots.txt", opts.OtherCacheControl},
		{"pdf", "docs/guide.pdf", opts.OtherCacheControl},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheControlForFile(tt.file, &opts)
			if got != tt.want {
				t.Errorf("cacheControlForFile(%q) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}

func TestCacheControlForFile_CustomPolicies(t *testing.T) {
	opts := Options{
		HTMLCacheControl:  "no-store",
		AssetCacheControl: "public, max-age=600",
		OtherCacheControl: "private",
	}

	tests := []struct {
		file string
		want string
	}{
		{"index.html", "no-store"},
		{"style.css", "public, max-age=600"},
		{"data.json", "private"},
		{"about", "no-store"}, // no extension -> HTML policy
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got := cacheControlForFile(tt.file, &opts)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
