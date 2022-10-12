using AtHackers.Exceptions;
using AtHackers.Unifier;
using BCrypt.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PreLibraryTest.Tests;
[TestClass]
public class LibraryValidatesAsRequired
{
    [TestMethod]
    public void Library_Validates_SHA256_HASH_AS_REQUIRED()
    {
        //Arrange
        string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword", "SHA256");
        //act
        var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA256");
        Assert.IsTrue(validateStatus);
        Assert.IsFalse(AtHackerHashProvider.ValidatePassword("MyPasswo", PasswordHash, "SHA256")); //Passes as a result of incorrect password passed

    }
    [TestMethod]
    public void Library_Validates_SHA_384_AS_Required()
    {
        //Arrange
        string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword", "SHA384");
        //act
        var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA384");
        Assert.IsTrue(validateStatus);
        Assert.IsFalse(AtHackerHashProvider.ValidatePassword("MyPasswo", PasswordHash, "SHA384")); //Passes as a result of incorrect password passed
        //Assertion To Ensure an exception is thrown on passing an incorrect hashAlgorithm
        Assert.ThrowsException<AssertFailedException>(() => Assert.IsTrue(AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA256")));

    }
    [TestMethod]
    public void Library_Validates_SHA_512_AS_Required()
    {
         //Arrange
        string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword", "SHA512");
        //act
        var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA512");
        Assert.IsTrue(validateStatus);
        Assert.IsFalse(AtHackerHashProvider.ValidatePassword("MyPasswo", PasswordHash, "SHA384")); //Passes as a result of incorrect password passed
        //Assertion To Ensure an exception is thrown on passing an incorrect hashAlgorithm
        Assert.ThrowsException<AssertFailedException>(() => Assert.IsTrue(AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA256")));
    }
    [TestMethod]
    public void Library_Validates_Default_HashFunction_AS_Required()
    {
         //Arrange
        string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword");
        //act
        var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash);
        Assert.IsTrue(validateStatus);
        Assert.IsFalse(AtHackerHashProvider.ValidatePassword("MyPasswo", PasswordHash)); //Passes as a result of incorrect password passed
        //Assertion To Ensure an exception is thrown on passing an incorrect hashAlgorithm
        Assert.ThrowsException<InvalidSaltException>(() => Assert.IsTrue(AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "SHA256")));
    }
    [TestMethod]
    public void Library_Validates_IsEnhancedBCRYPT_HashFunction_AS_Required()
    {
         //Arrange
        string PasswordHash = AtHackerHashProvider.GenerateHash("MyPassword","BCRYPT",false,true);
        //act
        var validateStatus = AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash,"BCRYPT",true);
        Assert.IsTrue(validateStatus);
        Assert.IsFalse(AtHackerHashProvider.ValidatePassword("MyPasswo", PasswordHash)); //Passes as a result of incorrect password passed
        //Assertion To Ensure an exception is thrown on passing an incorrect hashAlgorithm
        Assert.ThrowsException<AssertFailedException>(() => Assert.IsTrue(AtHackerHashProvider.ValidatePassword("MyPassword", PasswordHash, "BCRYPT",false)));
    }
   [TestMethod]
    public void Library_Cannot_Validate_UnSafeHash()
    {
         var passwordhash = AtHackerHashProvider.GenerateHash("pwd","sha256",true);
         Assert.ThrowsException<InvalidSaltException>(() => AtHackerHashProvider.ValidatePassword("pwd",passwordhash,"sha256"));

    }

}
