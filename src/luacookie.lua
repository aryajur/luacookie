-- Module to handle cookies

local url = require("net.url")
local string = string
local os = os
local table = table
local tonumber = tonumber
local type = type
local setmetatable = setmetatable
local pairs = pairs

-- For debug only
local print = print


-- Create the module table here
local M = {}
package.loaded[...] = M
_ENV = M		-- Lua 5.2+

_VERSION = "0.15.11.16"

local parseDate
do
	local function genCharClass(codeList)
		local cc = "["	-- character class
		for i = 1,#codeList do
			if type(codeList[i]) == "table" then
				-- this is a range
				cc = cc..string.char(codeList[i][1]).."-"..string.char(codeList[i][2])
			else
				cc = cc..string.char(codeList[i])
			end
		end
		return cc.."]"
	end
	-- Dates grammar. See https://tools.ietf.org/html/rfc6265#section-5.1.1
	-- Step 1:
	local delimList = {0x09,{0x20,0x2f},{0x3B,0x40},{0x5B,0x60},{0x7B,0x7E}}
	local nonDelimList = {{0x00,0x08},{0x0A,0x1F},{0x30,0x39}, string.byte(":"),{0x41,0x5a},{0x61,0x7a},{0x7F,0xFF}}
	local nonDigitList = {{0x00,0x2f},{0x3a,0xff}}
	local monthList = {jan=1,feb=2,mar=3,apr=4,may=5,jun=6,jul=7,aug=8,sep=9,oct=10,nov=11,dec=12}
	local digitList = {{0x30,0x39}}
	local delim = genCharClass(delimList)
	local nonDelim = genCharClass(nonDelimList)
	local nonDigit = genCharClass(nonDigitList)
	local digit = genCharClass(digitList)
	local dateTokenPat = nonDelim..nonDelim.."*"
	parseDate = function(dateString)
		-- Add an extra delimiter
		local dateTime = {}
		local found_time,found_dom,found_month,found_year
		if type(delimList[1]) == "table" then
			dateString = dateString..string.char(delimList[1][1])
		else
			dateString = dateString..string.char(delimList[1])
		end
		-- Loop for all date tokens
		for dt in dateString:gmatch("("..dateTokenPat..")"..delim..delim.."*") do	-- Step 2 
			if not found_time and dt:match("^"..string.rep(digit..digit.."?",3,":")..nonDigit.."*.*$") then
				found_time = true
				dateTime.hour,dateTime.min,dateTime.sec = dt:match("^"..string.rep("("..digit..digit.."?)",3,":")..nonDigit.."*.*$")
				dateTime.hour,dateTime.min,dateTime.sec = tonumber(dateTime.hour),tonumber(dateTime.min),tonumber(dateTime.sec)
			elseif not found_dom and dt:match("^"..digit..digit.."?"..nonDigit.."*.*$") then
				found_dom = true
				dateTime.day = tonumber(dt:match("^("..digit..digit.."?)"..nonDigit.."*.*$"))
			elseif not found_month and dt:match("^([%l%u][%l%u][%l%u]).*") and monthList[dt:match("^([%l%u][%l%u][%l%u]).*"):lower()] then
				found_month = true
				dateTime.month = monthList[dt:match("^([%l%u][%l%u][%l%u]).*"):lower()]
			elseif not found_year and dt:match("^"..digit..digit..digit.."?"..digit.."?"..nonDigit.."*.*") then
				found_year = true
				dateTime.year = tonumber(dt:match("^("..digit..digit..digit.."?"..digit.."?)"..nonDigit.."*.*"))
				if dateTime.year >= 70 and dateTime.year <= 99 then		-- Step 3
					dateTime.year = dateTime.year + 1900
				elseif dateTime.year >= 0 and dateTime.year <= 69 then 
					dateTime.year = dateTime.year + 2000
				end
			end		-- token match if-else ends here
		end		-- for dt (date token) gmatch loop ends here
		if not found_time or not found_dom or not found_month or not found_year then
			return nil	-- Step 5.a
		elseif dateTime.day < 1 or dateTime.day > 31 then
			return nil	-- Step 5.b
		elseif dateTime.year < 1601 then
			return nil	-- Step 5.c
		elseif dateTime.hour > 32 then
			return nil
		elseif dateTime.min > 59 then
			return nil
		elseif dateTime.sec > 59 then
			return nil
		end
		return dateTime
	end		-- function parseDate ends here

end


local function canonicalize(hostName)
	return hostName
end

-- parsing the cookie according to the algorithm given at https://tools.ietf.org/html/rfc6265#section-5.2
local function parse_set_cookie(s,requestURI)
	if not requestURI then return nil,"Need the request URI as the second argument" end
	local cookie = {}
	cookie.reqURI = url.parse(requestURI)
	cookie.reqURI.host = canonicalize(cookie.reqURI.host)
	-- calculate the default path according to https://tools.ietf.org/html/rfc6265#section-5.1.4
	if cookie.reqURI.path == "" or cookie.reqURI.path == [[/]] then
		cookie.defPath = [[/]]
	else
		if cookie.reqURI.path:sub(-1,-1) == [[/]] then
			cookie.defPath = cookie.reqURI.path:sub(1,-2)
		else
			cookie.defPath = cookie.reqURI.path
		end
	end
	-- Step 2:
	if not s:find("=") then
		return nil
	end
	-- Step 1:
	local st = s:find(";")
	if st then
		cookie.name,cookie.value = s:sub(1,st-1):match("^%s*(.-)%s*=%s*(.-)%s*$")	-- steps 3 and 4
	else
		cookie.name,cookie.value = s:match("^%s*(.-)%s*=%s*(.-)%s*$")	-- steps 3 and 4
	end
	cookie.created = os.date("!*t")		-- see https://tools.ietf.org/html/rfc6265#section-5.3
	cookie.accessed = cookie.created
	cookie.attributes = {}
	if cookie.name == "" then		-- step 5
		return nil
	end
	local knownAttr = {
		expires=parseDate,
		["max-age"] = function(val)
			if not val:sub(1,1):match("[0-9%-]") then
				return nil
			end
			if val:sub(2,-1):match("[^0-9]") then
				return nil
			end
			local delSecs = tonumber(val)
			if delSecs <= 0 then
				return os.date("!*t",0)
			else
				return os.date("!*t",os.time()+delSecs)
			end
		end,
		domain = function(val)
			if val == "" then
				return nil
			end
			if val:sub(1,1) == "." then
				return val:sub(2,-1):lower()
			else
				return val:lower()
			end
		end,
		path = function(val)
			if val == "" or val:sub(1,1) ~= [[/]] then
				return defPath
			else
				return val
			end
		end,
		secure = function(val)
			return true
		end,
		httponly = function(val)
			return true
		end
	}
	if st then
		-- We have the attributes as well
		local attr = s:sub(st+1,-1):match("^%s*(.-)%s*$")	-- Step 2 Attributes
		local currAttr, attrName,attrVal
		while attr ~= "" do	-- Step 1 Attributes
			st = attr:find(";")
			if st then		-- Step 3 Attributes
				currAttr = attr:sub(1,st-1)
				attr = attr:sub(st + 1,-1)
			else
				currAttr = attr
				attr = ""
			end
			if currAttr:find("=") then
				attrName,attrVal = currAttr:match("^%s*(.-)%s*=%s*(.-)%s*$")
			else
				attrName = currAttr:match("*%s*(.-)%s*$")
				attrVal = ""
			end
			-- Now add the attribute to the cookie table after processing
			if knownAttr[attrName:lower()] then
				local parsedVal = knownAttr[attrName:lower()](attrVal)
				if parsedVal then
					cookie.attributes[#cookie.attributes + 1]={attrName:lower(), parsedVal}
				end
			end		-- if not found then ends
		end		-- while attr ~= "" do ends
	end	-- if no ; found condition
	return cookie
end		-- function parse_set_cookie(s,requestURI) ends

-- Function to remove excess cookies from the store in the priority described here: https://tools.ietf.org/html/rfc6265#section-5.3
local function cleanupStore(store)
	-- First clean up expired cookies
	for i = #store,1,-1 do
		if os.time(store[i].expires) < os.time() then
			table.remove(store,i)
		end
	end
	-- Now remove excess cookies
	if #store > 3000 then
		-- Create a table wrt domain names and their cookes
		local domEntries = {}
		for i = 1,#store do
			local found
			for j = 1,#domEntries do
				if domEntries[j][1] == store[i].domain then
					domEntries[j][2] = domEntries[j][2] + 1
					found = true
					break
				end
			end
			if not found then
				domEntries[#domEntries + 1] = {store[i].domain,1}
			end
		end
		table.sort(domEntries,function(one,two)
				return one[2] < two[2]
			end
		)
		local toDel = {}
		for i = #domEntries,1,-1 do
			if domEntries[i][2] <=50 then
				break
			end
			toDel[#toDel + 1] = domEntries[i]
			toDel[#toDel][2] = toDel[#toDel][2]-50
		end
		for i = 1,#toDel do
			local delList = {}
			for j = 1,#store do
				if store[j].domain == toDel[i][1] then
					delList[#delList + 1] = j
				end
			end
			-- Sort them with accessed
			table.sort(delList,function(one,two)
					return os.time(store[one].accessed) < os.time(store[two].accessed)
				end
			)
			local newStore = {}
			for j = 1,#store do
				local found
				for k = 1,toDel[i][2] do
					if delList[k] == j then
						found = true
						break
					end
				end
				if not found then
					newStore[#newStore + 1] = store[j]
				end
			end
			store = newStore
		end
		-- Now we need to delete 3000-sum additional entries
		-- Sort in descending order
		table.sort(store,function(one,two)
				return os.time(one.accessed) > os.time(two.accessed)
			end
		)
		local sum = #store
		for i = 1,3000-sum do
			store[sum+1-i] = nil
		end
	end		-- if #store > 3000 then ends
	return store,#store
end

local function addCookieToStore(store,cookie)
	store = cleanupStore(store)
	local entry = {}
	-- Transfer everything except attributes
	for k,v in pairs(cookie) do
		if k ~= "attributes" then
			entry[k] = v
		end
	end
	-- For the next code see https://tools.ietf.org/html/rfc6265#section-5.3
	local lmaxage,lexpires,ldomain,lpath,lsecure,lhttponly
	for i = #cookie.attributes,1 do
		if not lmaxage and cookie.attributes[i][1] == "max-age" then
			lmaxage = i
		elseif not lexpires and cookie.attributes[i][1] == "expires" then
			lexpires = i
		elseif not ldomain and cookie.attributes[i][1] == "domain" then
			ldomain = i
		elseif not lpath and cookie.attributes[i][1] == "path" then
			lpath = i
		elseif not lsecure and cookie.attributes[i][1] == "secure" then
			lsecure = i
		elseif not lhttponly and cookie.attributes[i][1] == "httponly" then
			lhttponly = i
		end
	end
	if lmaxage then
		entry.persistent = true
		entry.expires = cookie.attributes[lmaxage][2]
	elseif lexpires then
		entry.persistent = true
		entry.expires = cookie.attributes[lexpires][2]
	else
		entry.expires = {day=18,min=14,sec=7,hour=19,month=1,year=2038}		-- Largest representable time by os.time
	end
	if ldomain then
		entry.domain = cookie.attributes[ldomain][2]
	else
		entry.domain = ""
	end
	-- Step 6
	------NEED TO FINISH THIS BY CALCULATING THE CANOCICALIZED REQUEST-HOST
	if entry.domain ~= "" then
		-- Check here if the domain does not match the canonicalized request-host
		if entry.domain ~= entry.reqURI.host then
			print("Domain is "..entry.domain.." while the host was "..entry.reqURI.host)
		end
	else
		entry.hostOnly = true
		entry.domain = entry.reqURI.host	-- This is just the host (haven't done any canonicalization)
	end
	------------------------------------------------------------------------
	if lpath then
		entry.path = cookie.attributes[lpath][2]
	else
		entry.path = entry.defPath
	end
	if lsecure then
		entry.secure = true
	end
	if lhttponly then
		entry.httponly = true
	end
	-- Check whether a similar cookie exists
	local entryIndex
	for i = 1,#store do
		local oldCookie = store[i]
		if oldCookie.name == entry.name and oldCookie.domain == entry.domain and oldCookie.path == entry.path then
			entry.created = oldCookie.created
			entryIndex = i
			break
		end
	end
	entryIndex = entryIndex or (#store + 1)
	store[entryIndex] = entry
	return store,entryIndex
end

-- As described here: https://tools.ietf.org/html/rfc6265#section-5.1.3
local function domainMatch(domain1,domain2)
	if domain1 == domain2 then
		return true
	end
	-- Need to implement the second condition
end

local function pathMatch(reqPath,cookiePath)
	if cookiePath == reqPath then
		return true
	end
	if reqPath:sub(1,#cookiePath) == cookiePath and cookiePath:sub(-1,-1) == [[/]] then
		return true
	end
	if reqPath:sub(2,#cookiePath+1) == cookiePath and reqPath:sub(1,1) == [[/]] then
		return true
	end
	return false
end

-- From here https://tools.ietf.org/html/rfc6265#section-5.4
local function getCookieHeader(store,requestURI)
	store = cleanupStore(store)
	local reqURI = url.parse(requestURI)
	reqURI.host = canonicalize(reqURI.host)
	local cookieList = {}
	local currTime = os.date("!*t")
	-- Step 1
	for i = 1,#store do
		if ((store[i].hostOnly and store[i].domain == reqURI.host) or 
		  (not store[i].hostOnly and domainMatch(store[i].domain, reqURI.host))) and
		  pathMatch(reqURI.path,store[i].path) and 
		  ((store[i].secure and reqURI.scheme == "https") or not store[i].secure) then
			cookieList[#cookieList + 1] = store[i]
			cookieList[#cookieList].accessed = currTime		-- Step 3
		end		  
	end
	-- Step 2
	table.sort(cookieList,function(one,two)
			if one.path == two.path then
				return os.time(one.created) < os.time(two.created)
			else
				return #one.path > #two.path
			end
		end
	)
	local sendcookie = ""
	for i = 1,#cookieList do
		sendcookie = sendcookie..cookieList[i].name.."="..cookieList[i].value.."; "
	end
	sendcookie = sendcookie:sub(1,-3)	-- remove the last ; and space
	return {
		Cookie = sendcookie
	}
end

local function endSession(store)
	cleanupStore(store)
	for i = #store,1 do
		if not store.persistent then
			store[i] = nil
		end
	end
	return store,#store
end

function new()
	local store = {}
	local storeMT = {
		__index = {
			add = function(header,requestURI)
				if not header["set-cookie"] then
					return nil,"Login Cookie not found."
				end
				--print("ADD COOKIE TO STORE:")
				--print(header["set-cookie"])
				local i = 1
				local full = header["set-cookie"]..", ENDMARKER="
				local st,stp,cookie,nextCookie
				while true do
					st,stp,cookie,i,nextCookie = full:find("(.-)%s*,()%s*([^;]+)=",i)
					if not nextCookie then break end
					local c,msg = parse_set_cookie(cookie,requestURI)
					if not c then return nil,msg end
					store,msg = addCookieToStore(store,c)
					if not store then return nil,msg end
				end
				--print("Number of cookies in store: ",#store)
				return true
			end,
			endSession = function()
				return endSession(store)
			end,
			getCookieHeader = function(requestURI)
				--print("GET COOKIE HEADER:")
				--print(getCookieHeader(store,requestURI))
				return getCookieHeader(store,requestURI)
			end
		}
	}
	
	return setmetatable({},storeMT)
end

