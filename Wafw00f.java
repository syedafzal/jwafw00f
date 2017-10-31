/*
Jwafw00f : A java version of wafw00f.
Notice from original work :

Copyright (c) 2009, {Sandro Gauci|Wendel G. Henrique}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of EnableSecurity or Trustwave nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.

*/
import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import java.util.*;

public class Wafw00f
{
	public static final String version="0.0.1";
	static boolean useproxy=false;
	static boolean followredirect=false;
	static boolean except=false;
	static boolean log=false;
	static boolean info=true;
	static Proxy proxy; 
	static String proxyHost; 
	static String proxyPort;
	static String isitwaf; 
	public static void main(String args[])
	{
		printBanner();
		Jwafw00f.setWafMap();
		try
			{
				String targetlist[]=null;
				int route=0,verbose=1;
				for(String input:args)
					{						
						/*
							0 : allwaf || generics
							1 : allwaf
							2 : isit
							-1 : abort 
						*/
						input.trim();
						if(input.toLowerCase().startsWith("proxy"))
						{
							int sep=input.indexOf(":");
							String host=input.substring(7,sep);
							String port=input.substring(sep+1);
							useproxy=true;
							proxyHost=host;
							proxyPort=port;
						}
						if(input.toLowerCase().startsWith("verbose"))
						{
							verbose=Integer.parseInt(input.substring(9));
							
						}
						if(input.toLowerCase().startsWith("isit"))
						{
							String wafs=input.substring(5);
							isitwaf=wafs;
							route=2;
						}
						if(input.toLowerCase().startsWith("findall"))
						{
							route=1;
						}
						if(input.toLowerCase().startsWith("redirect"))
						{
						
							if(input.substring(10).toLowerCase().equals("true"))
							followredirect=true;
						}
						if(input.toLowerCase().startsWith("list"))
						{
							Jwafw00f.printWafMap();
						}
						
						if(input.toLowerCase().startsWith("http"))
						{
							setVerbose(verbose);
							String target=input;
							targetlist=target.split(",");										
						}
						
					}
				try { 
						for(String subject:targetlist)
							{
								Jwafw00f instance=new Jwafw00f(subject,route);
										
								Thread execute=new Thread(instance);
								execute.start();
							}
					}
				catch(Exception e)
					{
						System.out.println(e.getMessage());
					}
									
			}
		catch(Exception e)
			{
				System.out.println("Error "+e.getMessage());
				e.printStackTrace();
			}
		
	}
		
	static void setVerbose(int level)
		{	
			boolean verb[]=new boolean[3];
			for(int i=0;i<3;i++)
				verb[i]=false;
			for(int i=0;i<level;i++)
				verb[i]=true;
				
			info=verb[0];
			log=verb[1];
			except=verb[2];
		}
	static void printUsage()
		{
			
		}
	
	static void printBanner()
		{
			String label[]={
							"     v0.1                   ___             __     __      ___ ",
							"     _                    /'___)          /' _`\ /' _`\  /'___)",
							"    (_) _   _   _    _ _ | (__  _   _   _ | ( ) || ( ) || (__  ",
							"    | |( ) ( ) ( ) /'_` )| ,__)( ) ( ) ( )| | | || | | || ,__) ",
							"    | || \_/ \_/ |( (_| || |   | \_/ \_/ || (_) || (_) || |    ",
							" _  | |`\___J___/'`\__,_)(_)   `\___J___/'`\___/'`\___/'(_)    ",
							"( )_| |  Based on Works of Sandro Gauci && Wendel G. Henrique  ",
							"`\___/'    			   By Syed Afzal [ syed@syedafzal.in ]  "
							};
			for(String line : label)
			System.out.print(line+"\n");
		}
}

class Jwafw00f implements Runnable
{
	/* Controlled By verbose*/
	static void except(String s)
	{
		if(Wafw00f.except)
		System.out.println(s);
	}
	static void log(String s)
	{
		if(Wafw00f.log)
		System.out.println(s);
	}
	static void info(String s)
	{
		if(Wafw00f.info)
		System.out.println(s);
	}
	static void setWafMap()
	{
			wafmap=new HashMap<String,Integer>();
		
			wafmap.put("ibm",0);
			wafmap.put("ibmdatapower",1);         
			wafmap.put("profense",2);
			wafmap.put("modsecurity",3);
			wafmap.put("isaserver",4);
			wafmap.put("netcontinuum",5);
			wafmap.put("hyperguard",6);
			wafmap.put("barracuda",7);
			wafmap.put("airlock",8);
			wafmap.put("binarysec",9);
			wafmap.put("f5trafficshield",10);
			wafmap.put("f5asm",11);
			wafmap.put("teros",12);
			wafmap.put("denyall",13);
			wafmap.put("bigip",14);
			wafmap.put("netscaler",15);
			wafmap.put("webscurity",16);
			wafmap.put("webknight",17);
			wafmap.put("urlscan",18);
			wafmap.put("secureiis",19);
			wafmap.put("dotdefender",20);
			wafmap.put("beeware",21);
			wafmap.put("imperva",22);
			// wafmap.put("modsecuritypositive",23);
			
	}
	static void printWafMap()
	{
		System.out.println(wafmap.keySet());
	}
	HttpURLConnection makeConnection(String strurl)
	{
		HttpURLConnection con=null;
		try 
			{
				URL url=new URL(strurl);
				if(Wafw00f.useproxy)
				{
					con=(HttpURLConnection)url.openConnection(Wafw00f.proxy);
				}
				else
				{	
					con=(HttpURLConnection)url.openConnection();
				}
				con.setInstanceFollowRedirects(Wafw00f.followredirect);
			}
			catch (MalformedURLException m)
			{
				log("Bad URL "+strurl);
				except(m.getMessage());
			}
			catch(Exception e)
			{
				log("Exception in makeConnection");
				except(e.getMessage());
			}	
		finally { return con;}
	}	

	/* Overloaded version */
	HttpURLConnection makeConnection(URL url2,String path)
	{
		HttpURLConnection con=null;
		try 
			{
				URL url=new URL (url2,path);
				if(Wafw00f.useproxy)
				{
					con=(HttpURLConnection)url.openConnection(Wafw00f.proxy);
				}
				else
					con=(HttpURLConnection)url.openConnection();
			
				con.setInstanceFollowRedirects(Wafw00f.followredirect);
			}
		catch (MalformedURLException m)
			{
				log("Bad URL "+url2.toString()+path);
				except(m.getMessage());
			}
			catch(Exception e)
			{
				log("Exception in makeConnection");
				except(e.getMessage());
			}	
		finally { return con;}
	}	
	 	
    static final String AdminFolder = "/Admin_Files/";
    static final String xssstring = "<script>alert(xss)</script>";
    static final String dirtravstring = "../../../../etc/passwd";
    static final String cleanhtmlstring = "<invalid>hello";
    static final String isaservermatch = "Forbidden ( The server denied the specified Uniform Resource Locator (URL). Contact the server administrator.  )";
	private URL url;
	private HttpURLConnection con;
	private HttpURLConnection attacks[];
	private Map<String,String> knowledge;
	private int selectroute;
	interface TestWaf 
	{
        boolean test();
    }
	private TestWaf[] testwaf;
	private static Map<String,Integer> wafmap;
	private CookieManager manager;
	private	CookieStore cs;
	Jwafw00f(String targeturl,int route)
	{
		try 
			{
				con=makeConnection(targeturl);
				url=con.getURL();
				selectroute=route;
				knowledge=new HashMap<String , String >();
				manager = new CookieManager();
				CookieHandler.setDefault(manager);
				cs = manager.getCookieStore();
				if(con.getResponseCode()!=200)
				{
					info(" Target Host Not Up. Aborting.");
					selectroute=-1;
				}			
			}
		catch(MalformedURLException e)
			{
				info("Bad URL");
				except("Bad URL "+e.getMessage());
			}
		catch(Exception e)
			{
				except("Bad URL "+e.getMessage());
			}
	}

	/*  the main action */
	public void run()
	{
	try {
		populateWaf();
		if(selectroute<2)
		{
			
			for(int i=0;i<testwaf.length;i++)
				{
					info("trying testwaf : "+i);
					if(testwaf[i].test())
					{
						String text="Detected : "++" in "+url.toString();
						info(text);						
						if(selectroute==0)
						return;
					}
				}
			if(selectroute==0)
				{
					if(genericDetect())
					{
						String text="Possible Waf detected in "+url.toString()+" "+knowledge.get("genericreason");
						info(text);
					}
					else
					{
						info("No Waf detected for "+url.toString());
					}
				}
		
		}
		if(selectroute==2)
		{
			String waf=Wafw00f.isitwaf;
			
			if(waf!=null)
			{
				String waflist[]=waf.split(",");
				for(String testcase:waflist)
				{
					info("checking 4 "+testcase);
					if(runWaf(testcase))
					{
						info(" Detected : "+testcase+" in "+url.toString());
					}
					else
					{
						info(" NOT Detected : "+testcase+" in "+url.toString());
					}
				}
			}
			else
			{
				info("unidentified waf name");
			}
		
		}
		}
	catch(Exception e) 
		{
			except(e.getMessage());
		}
	}
	
	
	private String urlEncode(String input)
	{
		String encoded="";
		for(int i=0; i<input.length(); i++)  
		encoded+="%"+String.format("%x", (byte)(input.charAt(i))); 

		return encoded;	
	    
	}	
	private HttpURLConnection cleanHtml()
	{
		String file=cleanhtmlstring+".html";
		return makeConnection(url,file);
	}
	
	private HttpURLConnection nonExistentFile()
	{
		int ran=new Random().nextInt(50000000);
		String file=ran+"eeeaaaa"+".html";
		return makeConnection(url,file);
	}
	
/*	private HttpURLConnection unknownMethod()
	{
		HttpURLConnection newcon=(HttpURLConnection)makeConnection(url.toString());
		
	}
*/
	
	private HttpURLConnection directoryTraversal()
	{
		return makeConnection(url,dirtravstring);
	}

	private HttpURLConnection invalidHost()
	{
		int ran=new Random().nextInt(9999999);
		String host=ran+"baabaa";
		HttpURLConnection c = makeConnection(url.toString());
		if(c!=null)
		c.setRequestProperty("Host",host);
		
		return c;
	}

	private HttpURLConnection cleanHtmlEncoded()
	{
		String file=cleanhtmlstring+".html";
		return makeConnection(url,file);
	}
	private HttpURLConnection xssStandard()
	{
		String file=xssstring+".html";
		return makeConnection(url,file);
	}
	private HttpURLConnection xssStandardEncoded()
	{
		String file=urlEncode(xssstring)+".html";
		return makeConnection(url,file);
	}		
	private HttpURLConnection cmdDotExe()
	{
		String path=url.getPath();
		path+="/"+"cmd.exe";
		return makeConnection(url,path);
	}
	private HttpURLConnection protectedFolder()
	{
		String path=url.getPath();
		path+="/"+AdminFolder;
		return makeConnection(url,path);
	}	
	private void populateAttacks()
	{
		 attacks=new HttpURLConnection[]{cmdDotExe(),directoryTraversal(),xssStandard(),protectedFolder(),xssStandardEncoded()};
	}
	private void populateWaf() throws Exception
	{
		testwaf = new TestWaf[] 
		{
			new TestWaf() { public boolean test() { return isibm(); } },
			new TestWaf() { public boolean test() { return isibmdatapower(); } },         
			new TestWaf() { public boolean test() { return isprofense(); } },
			new TestWaf() { public boolean test() { return ismodsecurity(); } },
			new TestWaf() { public boolean test() { return isisaserver(); } },
			new TestWaf() { public boolean test() { return isnetcontinuum(); } },
			new TestWaf() { public boolean test() { return ishyperguard(); } },
			new TestWaf() { public boolean test() { return isbarracuda(); } },
			new TestWaf() { public boolean test() { return isairlock(); } },
			new TestWaf() { public boolean test() { return isbinarysec(); } },
			new TestWaf() { public boolean test() { return isf5trafficshield(); } },
			new TestWaf() { public boolean test() { return isf5asm(); } },
			new TestWaf() { public boolean test() { return isteros(); } },
			new TestWaf() { public boolean test() { return isdenyall(); } },
			new TestWaf() { public boolean test() { return isbigip(); } },
			new TestWaf() { public boolean test() { return isnetscaler(); } },
			new TestWaf() { public boolean test() { return iswebscurity(); } },
			new TestWaf() { public boolean test() { return iswebknight(); } },
			new TestWaf() { public boolean test() { return isurlscan(); } },
			new TestWaf() { public boolean test() { return issecureiis(); } },
			new TestWaf() { public boolean test() { return isdotdefender(); } },
			new TestWaf() { public boolean test() { return isbeeware(); } },
			new TestWaf() { public boolean test() { return isimperva(); } }
		//, new TestWaf() { public boolean test() { return ismodsecuritypositive(); } }
		};	
	}
	
	 public boolean runWaf(String name)
	{
		
		if(wafmap.get(name)!=null)
		{
			int i=wafmap.get(name);
			return (testwaf[i].test());
		}
		else
		{
			info("waf not supported");
			return false;
		}
		
	}
	
	
	private boolean genericDetect() throws Exception
	{
		String reasons[]={"Blocking is being done at connection/packet level.",
						"The server header is different when an attack is detected.",
						"The server returned a different response code when a string trigged the blacklist.",
						"It closed the connection for a normal request.",
						"The connection header was scrambled."
						};
	HttpURLConnection r,clean;
	r=cleanHtml();
	if(r==null)
	{
		knowledge.put("genericreason",reasons[0]);
		knowledge.put("genericfound","true");
		return true;
	}
	clean=r;
        r = xssStandard();
        if (r==null)            
		{   
			knowledge.put("genericreason",reasons[0]);
			knowledge.put("genericfound","true");
			return true;
		}
	    HttpURLConnection  xssresponse = r;
        if (xssresponse.getResponseCode() != clean.getResponseCode())
         {  
			info("Server returned a different response when a script tag was tried");            
			String reason = reasons[2];
            reason += "\r\n";
            reason += "Normal response code is "+clean.getResponseCode();
            reason += "\n while the response code to an attack is "+xssresponse.getResponseCode();
    
			knowledge.put("genericreason",reason);
			knowledge.put("genericfound","true");
			return true;
		}
	    r = cleanHtmlEncoded();
        clean =r;
        r = xssStandardEncoded();
        if (r==null)            
		{   
			knowledge.put("genericreason",reasons[0]);
			knowledge.put("genericfound","true");
			return true;
		}
	    xssresponse = r;
        if( xssresponse.getResponseCode() != clean.getResponseCode())
           {
			info("Server returned a different response when a script tag was tried");
            String reason = reasons[2];
            reason += "\r\n";
            reason += "Normal response code is "+clean.getResponseCode();
            reason += "\n while the response code to an attack is "+xssresponse.getResponseCode();
			knowledge.put("genericreason",reason);
			knowledge.put("genericfound","true");
			return true;
			}
		
        String normalserver = con.getHeaderField("server");
        for( HttpURLConnection attack : attacks)        
        {    r = attack;             
          if (r==null)            
		{   
			knowledge.put("genericreason",reasons[0]);
			knowledge.put("genericfound","true");
			return true;
		}
		HttpURLConnection response = r;
        String attackresponse_server = response.getHeaderField("server");
            if( attackresponse_server!=null)
                if (attackresponse_server != normalserver)
                    info("Server header changed, WAF possibly detected");
                    log("attack response: "+attackresponse_server);
                    log("normal response: "+normalserver);
					String reason = reasons[1];
                    reason += "\r\nThe server header for a normal response is "+ normalserver;
                    reason += "\n while the server header a response to an attack is "+attackresponse_server;
			knowledge.put("genericreason",reason);
			knowledge.put("genericfound","true");
			return true;
		}	
		
        for(HttpURLConnection attack : attacks)
        {    r = attack;
          if (r==null)            
		{   
			knowledge.put("genericreason",reasons[0]);
			knowledge.put("genericfound","true");
			return true;
		}
		HttpURLConnection response= r;
		Map<String, List<String>> map = response.getHeaderFields();
           for (Map.Entry<String, List<String>> entry : map.entrySet())
           {       
            String key=entry.getKey();
			if( scrambledheader(key))
                { knowledge.put("genericreason",reasons[4]);
                 knowledge.put("genericfound","true");
                 return true;     
				}
           }
           return false;
		}
		return false;
	}
	private boolean scrambledheader(String header)
    {
		String c = "connection";
		if (header.length() != c.length())
        return false;
		if (header.equals(c))
        return false;
		for(int k=0;k<c.length();k++)
		{ 
			int ind=0;int occ1=0,occ2=0;
			char t=c.charAt(k);
			while(c.indexOf(t,ind)!=-1)
			{
				occ1++;
			}
			ind=0;
			while(header.indexOf(t,ind)!=-1)
			{
				occ2++;
			}
			if (occ1 != occ2)
			return false;
		
		}
    return true;
	}
	/* support */
	private boolean  matchHeader(HttpCookie header, boolean useattacks)
    {  
		boolean	detected=false;
        HttpURLConnection[] requests;
        
	try{	
        if (useattacks)
            {
				populateAttacks();
				requests=attacks;
				
			}	
        else{
				requests = new HttpURLConnection[]{con};
			}
			
        for (HttpURLConnection request : requests)            
        {    
			
            if(request==null)               
                continue;
            
			String r=request.getHeaderField(header.getName());
			if(r!=null)
				if(r.matches(header.getValue()))
					return(detected=true);
		}	
    }
	catch(Exception e){}
	finally {return detected;}
	}
	
	private boolean matchCookie(HttpCookie testcookie) 
	{
		boolean found=false;
		Object obj;
		List<HttpCookie> cookies;
		try
			{
			
				/*	obj = con.getContent();
					cookies = cs.getCookies();
					java.net.CookieStore rawCookieStore = ((java.net.CookieManager) CookieHandler.getDefault()).getCookieStore();

				*/	
				cookies = cs.get(url.toURI());
				if(cookies==null || cookies.isEmpty())
				{	
					info("cookie empty");
					return found;
				}	
				for (HttpCookie cookie : cookies)
					{
						info(cookie.getName());
						if(cookie.getName().matches(testcookie.getName()))
							return(found=true);
				
					}
			}
		catch(Exception e)
			{	
				except(e.getMessage());
			}
		finally
			{
				return found;
			}
	}
	// overloaded
	private boolean matchCookie(String testcookie)
	{
		boolean found=false;
		Object obj;
		List<HttpCookie> cookies;
		try
			{
				/*	obj = con.getContent();
					cookies = cs.getCookies();
					java.net.CookieStore rawCookieStore = ((java.net.CookieManager) CookieHandler.getDefault()).getCookieStore();

				*/	
				// info(testcookie);
				cookies = cs.get(url.toURI());
				if(cookies==null || cookies.isEmpty())
				{	
					info("cookie empty");
					return found;
				}	
				
				for (HttpCookie cookie : cookies)
					{
						// info("coo is "+cookie.getName());
						if(cookie.getName().matches(testcookie))
							return(found=true);
					}
			}
		catch(Exception e)
			{
				except(e.getMessage());
			}
		finally
			{
				return found;
			}
	}
	/* support ends */
	
	/*		*** Waf Detection Begins ***		*/
	
	private boolean isbigip()
	{
        return matchHeader(new HttpCookie("X-Cnection","^close$"), true);
    }
    private boolean iswebknight()  
	{
		boolean  detected = false;
		populateAttacks();
        for(HttpURLConnection attack : attacks)
         {   
            if (attack==null)                
                continue;
         
            try 
				{
					if(attack.getResponseCode() == 999)
					return(detected = true);
				}
			catch(Exception e)
				{
					except(e.getMessage());
					return false;
				}
		}
		return detected;
    }    
   private boolean ismodsecurity()
    {
		boolean  detected = false;
		populateAttacks();
        for(HttpURLConnection attack : attacks)
         {   
            if (attack==null)                
                continue;
			try {
					if (attack.getResponseCode() == 501)
					return(detected = true);
				}
			catch(Exception e)
				{
					except(e.getMessage());
					return false;
				}
        }
		return detected;
    }   
    private boolean isisaserver() 
    {  	
		boolean  detected = false;
        HttpURLConnection r =invalidHost();
        if (r ==null)
        return  detected; // need check
        try {
				if(r.getHeaderField("server").equalsIgnoreCase(isaservermatch))
				detected = true;
			}
		catch (Exception e)
			{
				except(e.getMessage());
				return false;
			}
		return detected;
    }
    private boolean issecureiis()  
	{
        // credit goes to W3AF
		boolean detected = false;
        HttpURLConnection r=con;
		String s="";
		if (r==null)
           return detected;
		
		try{	
				if (r.getResponseCode()==404)
				return detected;
        
		
				for(int i=0;i<1025;i++)
				s+="z";
        
				r.setRequestProperty("Transfer-Encoding",s);
				if( r.getResponseCode() == 404)
					detected = true;
			}
			catch(Exception e)
			{
				except(e.getMessage());
			}
        finally { return detected; }
    }
    
	/* Cookie Match Based Detections */
    private boolean isairlock()
    {    // credit goes to W3AF
		
        return matchCookie("^AL[_-]?(SESS|LB)");
    }
    private boolean isbarracuda()
    {  //  # credit goes to W3AF
        return matchCookie("^barra_counter_session");
    }
    private boolean isdenyall()  
    {
    // credit goes to W3AF
        if(matchCookie("^sessioncookie"))
            return true;
        // credit goes to Sebastien Gioria
        //   Tested against a Rweb 3.8
        // and modified by sandro gauci and someone else
        populateAttacks();
		try 
			{
		
				for(HttpURLConnection attack : attacks)
					{   
						HttpURLConnection r = attack;
						if( r==null)
						continue;
            
						if(r.getResponseCode() == 200)
							if(r.getResponseMessage().equals("Condition Intercepted"))
								return true;
					}
			}
		catch(Exception e)
			{
				except(e.getMessage());
				return false;
			}
			
		return false;
	}
    
    private boolean isbeeware()
    {
		//# disabled cause it was giving way too many false positives
        //# credit goes to Sebastien Gioria
        boolean detected = false;
		HttpURLConnection  r =xssStandard();
        if (r==null)
            return detected;  
        try 
			{
		
				if ((r.getResponseCode() != 200) || (r.getResponseMessage().equals("Forbidden")))
					r = directoryTraversal();
				if (r==null)
				return detected;  
        
				if(r.getResponseCode() == 403)
                if(r.getResponseMessage().equals("Forbidden"))
                    detected = true;
			}
		catch(Exception e)
			{
				except(e.getMessage());
			}
		finally {
					return detected;
				}
	}    
    private boolean isf5asm()
    { //    # credit goes to W3AF
        return matchCookie("^TS[a-zA-Z0-9]{3,6}");
    }
    private boolean isf5trafficshield()
    {
    if(matchHeader(new HttpCookie("cookie","^ASINFO"),false) || matchHeader(new HttpCookie("server","F5-TrafficShield"),false))         
        return true;
    else
        return false;
	}	

    private boolean isteros()
    {//    # credit goes to W3AF
        return matchCookie("^st8id");
    }
   private boolean isnetcontinuum()
   {
    //    # credit goes to W3AF
        return matchCookie("^NCI__SessionId");
    }
    private boolean isbinarysec()
	{
     //   # credit goes to W3AF
        return matchHeader(new HttpCookie("server","BinarySec"),false);
	}	
    private boolean ishyperguard()
	{
     //   # credit goes to W3AF
        return matchCookie("^WODSESSION");
    }
    private boolean isprofense()
	{
    /*    """
        Checks for server headers containing "profense"
        """  */
        return matchHeader(new HttpCookie("server","profense"),false);
    }    
    private boolean isnetscaler()
	{
    /*    """
        First checks if a cookie associated with Netscaler is present,
        if not it will try to find if a "Cneonction" or "nnCoection" is returned
        for any of the attacks sent
        """ */
    //    # NSC_ and citrix_ns_id come from David S. Langlands <dsl 'at' surfstar.com>
        log("net scalar called");

		if (matchCookie("^(ns_af|citrix_ns_id|NSC_)"))
            {
				System.out.println("netscalar detected.");
				return true;
			}
        if (matchHeader(new HttpCookie("Cneonction","close"),true))
            return true;
        if (matchHeader(new HttpCookie("nnCoection","close"),true))
            return true;
        info("scalar not found ");
		return false;
    						
	}
    private boolean isurlscan()  
	{
		boolean detected = false;
		String s="";
		
		for(int i=0;i<10;i++)
		s+="z";
		
		try 
			{
				HttpURLConnection con=makeConnection(url.toString());
				HttpURLConnection con2=makeConnection(url.toString());
		
				if(con==null)
					return false;
				if( con2==null)
					return false;
        
				con2.setRequestProperty("Translate",s);
				con2.setRequestProperty("If",s);
				con2.setRequestProperty("Lock-Token",s);
				con2.setRequestProperty("Transfer-Encoding",s);
        
				int code1=con.getResponseCode();
				int code2=con2.getResponseCode();
         
				if (code1!=code2)
				if (code2== 404)
                detected = true;
			}
		catch(Exception e)
			{
				except(e.getMessage());
			}
		finally 
		{	
			return detected;
		}	
    }
    private boolean iswebscurity()  
	{
		boolean detected = false;
		try 
			{
				HttpURLConnection r=makeConnection(url.toString());
		
				if(r==null) 
					return false;
				String newpath = url.getPath() + "?nx=@@";
				r = makeConnection(url,newpath);
				if(r==null) 
					return false;
        
				if(r.getResponseCode()== 403)
					detected = true;
			}
		catch(Exception e)
			{
				except(e.getMessage());
			}
		finally
			{
				return detected;
			}	
    }
    private boolean isdotdefender()
	{
     //   # thanks to j0e
        return matchHeader(new HttpCookie("X-dotDefender-denied", "^1$"),true);
	}
    private boolean isimperva() 
	{
		//# thanks to Mathieu Dessus <mathieu.dessus(a)verizonbusiness.com> for this
        //# might lead to false positives so please report back to sandro@enablesecurity.com
        populateAttacks();
		for(HttpURLConnection attack : attacks)
        {  HttpURLConnection  r = attack;
            
			if(r==null) 
				return false;
			try 
				{
					if(r.getHeaderFieldKey(0).contains("1.0"))
						return true;
				}
			catch(Exception e)
				{
					except(e.getMessage());
				}
			finally
			{
				return false;
			}	
		}	
		return false;
	}
    private boolean ismodsecuritypositive()
	{
        
        boolean detected = false;
        HttpURLConnection r=nonExistentFile();
		if (r == null)
            return detected;
		try
			{
				if( r.getResponseCode() != 302)
					return false;
				
				r =makeConnection(r.getURL(),(r.getURL().getPath()+"%00"));
				if (r == null)
				return detected;
			
				if( r.getResponseCode()==404 )
				detected=true;
			}
		catch(Exception e)
			{
				except(e.getMessage());	
			}
		finally
			{
				return detected;
			}	
    }
	
    private boolean isibmdatapower()
	{
     //   # Added by Mathieu Dessus <mathieu.dessus(a)verizonbusiness.com> 
       boolean detected = false;
        if(matchHeader(new HttpCookie("X-Backside-Transport", "^(OK|FAIL)"),false))
            detected = true;
        return detected;
	}

    private boolean isibm()
    {
		boolean detected = false;
        HttpURLConnection r = protectedFolder();
        if(r==null)
           detected = true;
        return detected;
	}

	/*		***	Waf Detection Ends ***		*/	

} // class ends
