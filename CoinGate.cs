using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

/// <summary>
/// CoinGate C# Class.
/// </summary>
public class CoinGate
{
    #region internal
    // Protected API Variable for acces by derived classes.
    //TODO: Perhaps would be more appropriate to use `private`
    protected string ApiId { get; set; }
    protected string ApiSecret { get; set; }
    protected string ApiKey { get; set; }
    //TODO: There may be issues with JP characters etc.
    private static readonly Encoding encoding = Encoding.UTF8;
    #endregion internal

    #region models
    /// <summary>
    /// Request model for the API calls which corresponds to API naming convention. 
    /// </summary>
    public class RequestParams
    {
        public string order_id { get; set; }
        public double price { get; set; }
        public string currency { get; set; }
        public string receive_currency { get; set; }
        public string callback_url { get; set; }
        public string cancel_url { get; set; }
        public string success_url { get; set; }
        public string description { get; set; }
    }
    /// <summary>
    /// Response Model returned to c# caller. 
    /// </summary>
    public class Response
    {
        public HttpStatusCode Status { get; set; }
        public string ResponseBody { get; set; }
    }
    #endregion models

    #region constructor_and_methods
    /// <summary>
    /// Constructor to for the CoinGate instance which will take in API user details. 
    /// </summary>
    /// <param name="apiId"></param>
    /// <param name="apiSecret"></param>
    /// <param name="apiKey"></param>
    public CoinGate(string apiId, string apiSecret, string apiKey)
    {
        // Set the API 
        // Early out if missing param. 
        if (string.IsNullOrEmpty(apiId) || string.IsNullOrEmpty(apiSecret) || string.IsNullOrEmpty(apiKey))
            throw new ArgumentNullException("Missing API constructor parameter.");
        // Set the API settings
        ApiId = apiId;
        ApiSecret = apiSecret;
        ApiKey = apiKey;
    }

    /// <summary>
    /// Construct and execute a test request with staticly assigned values. 
    /// </summary>
    /// <param name="url"></param>
    /// <param name="method"></param>
    /// <returns></returns>
    public Response TestRequest(string url, string method = "GET")
    {
        // Create the Request object with generic values. 
        var requestParams = new RequestParams()
        {
            callback_url = "http://example.com/callback/?id=1",
            cancel_url = "http://example.com/",
            currency = "EUR",
            description = "C# Test Method",
            order_id = "42",
            price = 100.00,
            receive_currency = "EUR",
            success_url = "http://example.com/success/?id=1"
        };
        //Return the request.
        return ApiRequest(url, requestParams, "post");
    }

    /// <summary>
    /// Main API request method. Will return a Http Statuc code and the body response in string format for parsing // casting. 
    /// </summary>
    /// <param name="url"></param>
    /// <param name="requestObject"></param>
    /// <param name="method"></param>
    /// <returns></returns>
    public Response ApiRequest(string url, RequestParams requestObject = null, string method = "GET")
    {
        // Return Object
        Response returnValue = new Response();
        try
        {
            // Create a request using a URL that can receive a post. 
            WebRequest request = WebRequest.Create(url);
            // Set the Method property of the request to POST.
            request.Method = method.ToUpper();

            // Variable building
            var timeNonce = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var message = timeNonce + ApiId + ApiKey;
            var signature = GetSignature(message);
            // Set headers for request
            request.Headers = new WebHeaderCollection();
            request.Headers.Add("Access-Key", ApiKey);
            request.Headers.Add("Access-Nonce", timeNonce.ToString());
            request.Headers.Add("Access-Signature", signature);
            // Create POST data and convert it to a byte array.
            string postData = parseRequestObject(requestObject);
            byte[] byteArray = encoding.GetBytes(postData);
            // Set the ContentType property of the WebRequest.
            request.ContentType = "application/x-www-form-urlencoded";
            // Set the ContentLength property of the WebRequest.
            request.ContentLength = byteArray.Length;
            // Get the request stream.
            Stream dataStream = request.GetRequestStream();
            // Write the data to the request stream.
            dataStream.Write(byteArray, 0, byteArray.Length);
            // Close the Stream object.
            dataStream.Close();
            // Get the response.
            WebResponse response = request.GetResponse();
            // Set Reponse status code
            returnValue.Status = ((HttpWebResponse)response).StatusCode;
            // Get the stream containing content returned by the server.
            dataStream = response.GetResponseStream();
            // Open the stream using a StreamReader for easy access.
            StreamReader reader = new StreamReader(dataStream);
            // Read the content.
            string responseFromServer = reader.ReadToEnd();
            // Set the return Content
            returnValue.ResponseBody += responseFromServer;
            // Clean up the streams.
            reader.Close();
            response.Close();

            // Return to sender
            return returnValue;
        }
        catch (WebException ex)
        {
            // If something went wrong we will suppress the Exception but return a header response to the caller. 
            returnValue.Status = ((HttpWebResponse)ex.Response).StatusCode;
            returnValue.ResponseBody = String.Format("{0} : {1}", ex.Response.Headers["status"], ex.Message);
        }
        // Return 
        return returnValue;
    }

    #endregion constructor_and_methods

    #region helpers
    /// <summary>
    /// Small function to parse the RequestParams object to URL friendly request
    /// </summary>
    /// <param name="reqObject"></param>
    /// <returns></returns>
    private string parseRequestObject(RequestParams reqObject)
    {
        var properties = from p in reqObject.GetType().GetProperties()
                         where p.GetValue(reqObject, null) != null
                         select p.Name + "=" + HttpUtility.UrlEncode(p.GetValue(reqObject, null).ToString());

        // TODO: Maybe some Sanitization here — Out of scope though of this Class. 
        string queryString = String.Join("&", properties.ToArray());
        // Send back formatted 
        return queryString;
    }

    /// <summary>
    /// Singature mapping which corresponds to php's 'hash_hmac'
    /// </summary>
    /// <param name="message"></param>
    /// <returns></returns>
    private string GetSignature(string message)
    {
        var secretKeyBytes = encoding.GetBytes(ApiSecret);
        //using the bytemap
        using (var hmacsha256 = new HMACSHA256(secretKeyBytes))
        {
            hmacsha256.ComputeHash(encoding.GetBytes(message));
            //Return the corresponding string for the signature request. 
            return hmacsha256.Hash.Aggregate(string.Empty, (current, b) => current + b.ToString("X2")).ToLower();
        }
    }
    #endregion helpers
}
