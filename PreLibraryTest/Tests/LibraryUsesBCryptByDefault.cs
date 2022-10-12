using AtHackers.Unifier;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PreLibraryTest.Tests;
[TestClass]
public class LibraryUsesBCryptByDefault
{
    [TestMethod]
    public void Library_Produces_BCrypt_By_Default()
    {
        //Arrange
        var password = "Saula Sheriffdeen Olamilekan";
        //Act
        var hash = AtHackerHashProvider.GenerateHash(password);
        //Assert
        StringAssert.Contains(hash, "2a");
        StringAssert.StartsWith(hash, "$");
        StringAssert.Contains(hash, "$2a$11$");
    }
    //PasswordHash Generated here uses BCrypt thus: The Validation Uses BCrypt
    private string Hash = AtHackerHashProvider.GenerateHash("Salam Bh@!_#");

    [TestMethod]
    public void Library_Validates_BCrypt_By_Default()
    {
       //Arrange
       string password = "Salam Bh@!_#";
       //Act
       var validateStatus = AtHackerHashProvider.ValidatePassword(password,Hash); 

       // Without the specification of an hash algorithm, the library uses BCrypt.
        //Assert
        Assert.IsTrue(validateStatus);
        //The assertion fails here owing to the fact that a wrong hash algorithm is passed.
        validateStatus = AtHackerHashProvider.ValidatePassword(password,Hash,"SHA256",true);
        Assert.IsTrue(validateStatus);// Fails because validateStatus is false
        Assert.IsFalse(validateStatus); // Passes because validateStatus is false
    }

}
