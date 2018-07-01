$TTL    86400
@ IN SOA voyager.amazon.com. admin.amazon.com. (
		  13         ; Serial number
		  3h         ; Refresh after 3 hours
		  1h         ; Retry after 1 hour
		  1w         ; Expire after 1 week
		  1h )       ; Negative Cache TTL of 1 hour

; Name servers
amazon.com. IN NS voyager.amazon.com.

; Mail exchange servers
;amazon.com. IN MX 10 voyager.amazon.com.

; Host addresses
;voyager.amazon.com. IN A 201.54.140.10
amazon.com. IN A 201.54.140.10

; Aliases
www.amazon.com. IN CNAME amazon.com.
