using AtHackers.Unifier;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PreLibraryTest.Tests;
[TestClass]
public class LibraryProducesRequireHashResult
{
    //Arrange
    public bool onlyHashRequired = false;
    public string password = "MyPassword";
    public int hashLengthPerAlgo = 0;

    [TestMethod]
    public void Library_Produces_Required_SHA512_Hash_Result()
    {
        //Act
        var hash = AtHackerHashProvider.GenerateHash(password, "SHA512");
        var hashArray = hash.Split("@");
        hashLengthPerAlgo = hashArray[1].Replace("&", "").Length;
        //Assert
        Assert.IsTrue(hash.Contains("@"));
        Assert.IsFalse(!hash.Contains("$"));
        Assert.AreEqual(128, hashLengthPerAlgo);
    }
    [TestMethod]
    public void Library_Produces_Required_SHA384_Hash_Result()
    {
        //Act
        var hash = AtHackerHashProvider.GenerateHash(password, "SHA384");
        var hashArray = hash.Split("@");
        hashLengthPerAlgo = hashArray[1].Replace("&", "").Length;
        Assert.IsTrue(hash.Contains("@"));
        Assert.IsFalse(!hash.Contains("$"));
        Assert.AreEqual(96, hashLengthPerAlgo);
    }
    [TestMethod]
    public void Library_Produces_Required_SHA256_Hash_Result()
    {
        //Act
        var hash = AtHackerHashProvider.GenerateHash(password, "SHA256");
        var hashArray = hash.Split("@");
        hashLengthPerAlgo = hashArray[1].Replace("&", "").Length;
        Assert.IsTrue(hash.Contains("@"));
        Assert.IsFalse(!hash.Contains("$"));
        Assert.AreEqual(64, hashLengthPerAlgo);
    }
    [TestMethod]
    public void Library_Produces_Ordinary_Hash()
    {
        // Assertion that a password hash is generated with no salt, peppers, this hash 
        // approach isn't safe for a password that needs to be stored because it is decodable with ease 
        // using several dehashing engines e.g CrackStation.Net Or HashKiller.co.uk
        var hash = AtHackerHashProvider.GenerateHash(password, "sha512", onlyHashRequired = true);
        Assert.IsTrue(onlyHashRequired == true && !hash.Contains("@"));
    }
    [TestMethod]
    public void Library_Produces_Valid_BCrypt_Hash()
    {
        var bCryptHash = AtHackerHashProvider.GenerateHash(password, "BCRYPT", false);
        //Assert.IsFalse(AtHackerHashProvider.ValidatePassword(password,bCryptHash,"BCRYPT",true)); // Failed Because a valid hash and pwd was passed
        Assert.IsTrue(AtHackerHashProvider.ValidatePassword(password, bCryptHash, "BCRYPT", true));

        // Validate Safe hash Using Bcrypt With Its Usual HashPassword();
        bCryptHash = AtHackerHashProvider.GenerateHash(password, "BCRYPT", false, false);
        Assert.IsTrue(AtHackerHashProvider.ValidatePassword(password, bCryptHash, "BCRYPT", false));
    }

}
