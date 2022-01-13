using EcryptAndDecrypt.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EcryptAndDecrypt.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private static IWebHostEnvironment _hostEnvironment;

        public HomeController(IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
        }

        public IActionResult Index()
        {
            var data = "Hello WorldI can see that the keys are correct, and the same code works fine in a single console application. I tried to look for a solution, (perhaps CspParameters is required?) but it's just making it more confusing at the moment";
            var encryptdat = EncryptUsingCertificate(data);
            Console.WriteLine(">>>>>>>>>EncryptUsingCertificate>>>>>>>>>>>");
            Console.WriteLine(encryptdat);
            Console.WriteLine(">>>>>>>>>>EncryptUsingCertificate>>>>>>>>>>");

            var orginaldata = DecryptUsingCertificate(encryptdat);

            Console.WriteLine(">>>>>>>>>DecryptUsingCertificate>>>>>>>>>>>");
            Console.WriteLine(orginaldata);
            Console.WriteLine(">>>>>>>>>>DecryptUsingCertificate>>>>>>>>>>");

            return View();



        }

        public IActionResult Privacy()
        {
            return View();
        }

        public static string EncryptUsingCertificate(string data)
        {
            try
            {
                

                byte[] byteData = Encoding.UTF8.GetBytes(data);
                string path = Path.Combine(_hostEnvironment.WebRootPath, "mycert.pem");
                var collection = new X509Certificate2Collection();
                collection.Import(path);
                var certificate = collection[0];
                var output = "";
                using (RSA csp = (RSA)certificate.PublicKey.Key)
                {
                    byte[] bytesEncrypted = csp.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
                    output = Convert.ToBase64String(bytesEncrypted);
                }
                return output;
             
            }
            catch (Exception ex)
            {
                return "";
            }
        }
        public static string DecryptUsingCertificate(string data)
        {
            try
            {
                byte[] byteData = Convert.FromBase64String(data);
                string path = Path.Combine(_hostEnvironment.WebRootPath, "mycertprivatekey.pfx");
                var Password = "123";//Note This Password is That Password That We Have Put On Generate Keys  
                var collection = new X509Certificate2Collection();
                collection.Import(System.IO.File.ReadAllBytes(path), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                X509Certificate2 certificate = new X509Certificate2();
                certificate = collection[0];
                foreach (var cert in collection)
                {
                    if (cert.FriendlyName.Contains("my certificate"))
                    {
                        certificate = cert;
                    }
                }
                if (certificate.HasPrivateKey)
                {
                    RSA csp = (RSA)certificate.PrivateKey;
                    var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                    var keys = Encoding.UTF8.GetString(csp.Decrypt(byteData,RSAEncryptionPadding.OaepSHA1));
                    return keys;
                }
            }
            catch (Exception ex)
            {

            }
            return null;
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
