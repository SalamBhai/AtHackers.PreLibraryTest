using System.Diagnostics;
using AtHackers.Exceptions;
using AtHackers.Hashers;
using AtHackers.Unifier;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace PreLibraryTest.Tests
{
    [TestClass]
    public class ATHACKERSTEST
    {
      
        
        [TestMethod]

        public void Library_Produces_Required_Hash_Result()
        {
            //Arrange
            //512: 128. 256: 64. 384: 96
            bool onlyHashRequired = false;
           string password = "MyPassword";
           int hashLengthPerAlgo = 0;
           //Act
           
           var hash = AtHackerHashProvider.GenerateHash(password,"SHA512");
           var hashArray = hash.Split("@");
           hashLengthPerAlgo =  hashArray[1].Replace("&","").Length;

           //Assert 
           //Assertion for a savehash generated with peppers & salts that aren't easy and impossible to decode 
           // Based on the correct hash function.
           // First Two Assertions Prove The same and applies to all other hash functions used in the Library,
           //The Last Exists For hash512
           Assert.IsTrue(hash.Contains("@"));
           Assert.IsFalse(!hash.Contains("$"));
           Assert.AreEqual(128, hashLengthPerAlgo);
           
           // SHA384 VALID HASH ASSERTION
           hash = AtHackerHashProvider.GenerateHash(password,"SHA384");
            hashArray = hash.Split("@");
           hashLengthPerAlgo = hashArray[1].Replace("&","").Length;
           Assert.AreEqual(96, hashLengthPerAlgo);

           // SHA256 VALID HASH ASSERTION
           hash = AtHackerHashProvider.GenerateHash(password,"SHA256");
           hashArray = hash.Split("@");
           hashLengthPerAlgo = hashArray[1].Replace("&","").Length;
           Assert.AreEqual(64, hashLengthPerAlgo);

           // Assertion that a password hash is generated with no salt, peppers, this hash 
           // approach isn't safe for a password that needs to be stored because it is decodable with ease 
           // using several dehashing engines e.g CrackStation.Net Or HashKiller.co.uk
           hash = AtHackerHashProvider.GenerateHash(password,"sha512",onlyHashRequired = true);
           Assert.IsTrue(onlyHashRequired == true && !hash.Contains("@"));

           //VALIDATE SAFE HASH using BCRYPT With Its Enhanced Hash Password Method
           var bCryptHash = AtHackerHashProvider.GenerateHash(password,"BCRYPT",false);
           //Assert.IsFalse(AtHackerHashProvider.ValidatePassword(password,bCryptHash,"BCRYPT",true)); // Failed Because a valid hash and pwd was passed
           Assert.IsTrue(AtHackerHashProvider.ValidatePassword(password,bCryptHash,"BCRYPT",true));
          
           // Validate Safe hash Using Bcrypt With Its Usual HashPassword();
           bCryptHash = AtHackerHashProvider.GenerateHash(password,"BCRYPT",false,false);
            Assert.IsTrue(AtHackerHashProvider.ValidatePassword(password,bCryptHash,"BCRYPT",false));
        }
        [TestMethod]
        public void Library_Validates_As_Required()
        {
            //Arrange
           string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword","BCRYPT",false,false);
           //Act
           //var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword",PasswordHash,"BCRYPT",true);
           //Assert For The Default Hash(The EnhanceHashPassword By BCrypt)
           //Assert.IsTrue(validateStatus); //Valid
            // var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword",PasswordHash,"SHA256");
            // //Assert For The SHA256 Hash
            // Assert.IsTrue(validateStatus);
            //  var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword",PasswordHash,"SHA384");
            // //Assert For The SHA384 Hash
            // Assert.IsTrue(validateStatus);

            // var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword",PasswordHash,"SHA512");
            // //Assert For The SHA512 Hash
            // Assert.IsTrue(validateStatus);
            var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword",PasswordHash,"BCRYPT",false);
            //Assert For The BCRYPT HashPassword() And (VerifyPassword()) methods
            Assert.IsTrue(validateStatus);

        }
        [TestMethod]
        public void Valid_Exception_Thrown()
        {
            //Arrange
            string password = AtHackerHashProvider.GenerateHash("password","SHA512",true);
            
            //Act
            Assert.ThrowsException<ValueCannotBeNullException>(() => AtHackerHashProvider.GenerateHash("","SHA512"));
            // Failed When: Assert.ThrowsException failed. When It:
            //Threw exception InvalidSaltException, but exception ValueCannotBeNullException was expected. 
             // Was Successful when a valid exception type was passed
            //Act 
            //Assert.ThrowsException<ArgumentException>(() => AtHackerHashProvider.ValidatePassword("",password));

            Assert.ThrowsException<InvalidSaltException>(() => AtHackerHashProvider.ValidatePassword("password",password,"SHA512"));

        }
        [TestMethod]
        public void Library_Produces_BCrypt_By_Default()
        {
             var password = "Saula Sheriffdeen Olamilekan";
             var hash = AtHackerHashProvider.GenerateHash(password);
             StringAssert.Contains(hash,"2a");
             StringAssert.StartsWith(hash,"$");
             StringAssert.Contains(hash,"$2a$11$");

        }

    }
}