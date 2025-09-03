<#
	LAST CHANGED: 2025/09/03
	

	powershell -ep bypass -f Start-WebServer.ps1

		
	.Synopsis
		Starts powershell webserver to serve static file(s)

	.Notes
		Version 1.6, 2024-01-31
		Author: Markus Scholtes
	
	.LINK
		https://github.com/MScholtes/WebServer


	.Example
		powershell "Invoke-WebRequest -Uri 'http://10.5.251.228:8080/test123.txt' -OutFile 'test123-COPY.txt'"

		powershell "Invoke-WebRequest -Uri 'http://10.5.251.228:8080/capture.png' -OutFile 'capture-COPY.png'"

#>
Param([STRING]$BINDING = 'http://+:8080/', [STRING]$BASEDIR = "")

if ($BASEDIR -eq "") {	# current filesystem path as base path for static content
	$BASEDIR = (Get-Location -PSProvider "FileSystem").ToString()
}
# convert to absolute path
$BASEDIR = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BASEDIR)

# MIME hash table for static content
$MIMEHASH = @{".avi"="video/x-msvideo"; ".crt"="application/x-x509-ca-cert"; ".css"="text/css"; ".der"="application/x-x509-ca-cert"; ".doc"="application/msword"; ".flv"="video/x-flv"; ".gif"="image/gif"; ".htm"="text/html"; ".html"="text/html"; ".ico"="image/x-icon"; ".jar"="application/java-archive"; ".jpeg"="image/jpeg"; ".jpg"="image/jpeg"; ".js"="application/javascript"; ".json"="application/json"; ".mjs"="application/javascript"; ".mov"="video/quicktime"; ".mp3"="audio/mpeg"; ".mp4"="video/mp4"; ".mpeg"="video/mpeg"; ".mpg"="video/mpeg"; ".pdf"="application/pdf"; ".pem"="application/x-x509-ca-cert"; ".pl"="application/x-perl"; ".png"="image/png"; ".rss"="application/rss+xml"; ".shtml"="text/html"; ".svg"="image/svg+xml"; ".txt"="text/plain"; ".war"="application/java-archive"; ".wmv"="video/x-ms-wmv"; ".xml"="application/xml"; ".xsl"="application/xml"}

# Starting the webserver
"$(Get-Date -Format s) Starting webserver..."
$LISTENER = New-Object System.Net.HttpListener
$LISTENER.Prefixes.Add($BINDING)
$LISTENER.Start()
$Error.Clear()

try
{
	"$(Get-Date -Format s) Webserver started."
	$WEBLOG = "$(Get-Date -Format s) Webserver started.`n"
	while ($LISTENER.IsListening)
	{
		# analyze incoming request
		$CONTEXT = $LISTENER.GetContext()
		$REQUEST = $CONTEXT.Request
		$RESPONSE = $CONTEXT.Response
		$RESPONSEWRITTEN = $FALSE

		# start logging
		$LOGLINE = "$(Get-Date -Format s) $($REQUEST.RemoteEndPoint.Address.ToString())"

		# is there a fixed coding for the request?
		$RECEIVED = '{0} {1}' -f $REQUEST.httpMethod, $REQUEST.Url.LocalPath
		$HTMLRESPONSE = "<!doctype html><html><body><code>$(Get-Date -format s)</code></body></html>"
		$RESULT = ''


		# create physical path based upon the base dir and url
		$CHECKDIR = $BASEDIR.TrimEnd("/\") + $REQUEST.Url.LocalPath
		$CHECKFILE = ""

		if (Test-Path $CHECKDIR -PathType Leaf) { # file found, path now in $CHECKFILE
			$CHECKFILE = $CHECKDIR
		}

		if ($CHECKFILE -ne "") 	{ 
			# static content available
			$EXTENSION = [IO.Path]::GetExtension($CHECKFILE)
			try {
							$BUFFER = [System.IO.File]::ReadAllBytes($CHECKFILE)
							$RESPONSE.ContentLength64 = $BUFFER.Length
							$RESPONSE.SendChunked = $FALSE
							if ($MIMEHASH.ContainsKey($EXTENSION)) { # known mime type for this file's extension available
								$RESPONSE.ContentType = $MIMEHASH.Item($EXTENSION)
							} else 	{ # no, serve as binary download
								$RESPONSE.ContentType = "application/octet-stream"
								$FILENAME = Split-Path -Leaf $CHECKFILE
								$RESPONSE.AddHeader("Content-Disposition", "attachment; filename=$FILENAME")
							}
							$RESPONSE.AddHeader("Last-Modified", [IO.File]::GetLastWriteTime($CHECKFILE).ToString('r'))
							$RESPONSE.AddHeader("Server", "Powershell Webserver/1.6 on ")
							$RESPONSE.OutputStream.Write($BUFFER, 0, $BUFFER.Length)
							# mark response as already given
							$RESPONSEWRITTEN = $TRUE
			}
			catch {
							# just ignore. Error handling comes afterwards since not every error throws an exception
			}
			
			if ($Error.Count -gt 0) { # retrieve error message on error
							$RESULT = "`nError while downloading '$CHECKFILE'`n`n"
							$RESULT += $Error[0]
							$Error.Clear()
			}
		} else {	# no file to serve found, return error
			if (!(Test-Path $CHECKDIR -PathType Container)) {
				$RESPONSE.StatusCode = 404
				$HTMLRESPONSE = '<!doctype html><html><body>Page not found</body></html>'
			}
		}

		# only send response if not already done
		if (!$RESPONSEWRITTEN) 	{
			# insert result string into HTML template
			$HTMLRESPONSE = $HTMLRESPONSE -replace '!RESULT', $RESULT

			# return HTML answer to caller
			$BUFFER = [Text.Encoding]::UTF8.GetBytes($HTMLRESPONSE)
			$RESPONSE.ContentLength64 = $BUFFER.Length
			$RESPONSE.AddHeader("Last-Modified", [DATETIME]::Now.ToString('r'))
			$RESPONSE.AddHeader("Server", "Powershell Webserver/1.6 on ")
			$RESPONSE.OutputStream.Write($BUFFER, 0, $BUFFER.Length)
		}

		# logging
		$LOGLINE += " $($RESPONSE.StatusCode) $($REQUEST.httpMethod) $($REQUEST.Url.PathAndQuery)"
		# ... to console
		$LOGLINE
		# and to log variable
		$WEBLOG += "$LOGLINE`n"

		# and finish answer to client
		$RESPONSE.Close()

		# received command to stop webserver?
		if ($RECEIVED -eq 'GET /exit' -or $RECEIVED -eq 'GET /quit') { # then break out of while loop
			"$(Get-Date -Format s) Stopping webserver..."
			break;
		}
	}
}
finally
{
	# Stop webserver
	$LISTENER.Stop()
	$LISTENER.Close()
	"$(Get-Date -Format s) Webserver stopped."
}