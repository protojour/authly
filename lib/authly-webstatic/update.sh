mkdir -p static/vendor

curl -O --output-dir ./static/vendor https://unpkg.com/@picocss/pico@2.0.6/css/pico.classless.min.css
curl -O --output-dir ./static/vendor https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js
curl -O --output-dir ./static/vendor https://unpkg.com/htmx-ext-json-enc@2.0.1/json-enc.js
curl -O --output-dir ./static/vendor https://unpkg.com/@carbon/icons@11.53.0/svg/32/login.svg
curl -O --output-dir ./static/vendor https://rsms.me/inter/font-files/InterVariable.woff2
curl -O --output-dir ./static/vendor https://rsms.me/inter/font-files/InterVariable-Italic.woff2

sed -i '1i<!-- Carbon Icons (C) 2015 IBM Corp. Licensed under Apache 2.0: https://github.com/carbon-design-system/carbon/blob/main/LICENSE -->' static/vendor/login.svg
sed -i 's/viewBox/id="icon" fill="currentColor" viewBox/g' static/vendor/login.svg
