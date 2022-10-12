using AtHackers.Exceptions;
using AtHackers.Unifier;
using BCrypt.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PreLibraryTest.Tests;

[TestClass]
public class LibraryThrowsValidException
{
    [TestMethod]
    public void Library_Throws_Invalid_Salt_Exception()
    {
        //Arrange
        var passwordHash = AtHackerHashProvider.GenerateHash("MyPassword", "SHA512", false);
        //Act
        //An Exception: InvalidSaltException Should Be Thrown for the unsafe hash generated above using either: sha256, sha384, and sha512 because it contains no salt
        Assert.ThrowsException<InvalidSaltException>(() => AtHackerHashProvider.ValidatePassword("MyPassword", passwordHash, "SHA512"));
    }
    [TestMethod]
    public void Library_Throws_Salt_Parse_Exception()
    {
        //Arrange
        var passwordHash = AtHackerHashProvider.GenerateHash("MyPassword", "BCRYPT", false);
        //An Exception: SaltParseException Should Be Thrown when there is misplacement of the plainInput in place of the HashedPassword using the BCRYPT Verify() methods
        Assert.ThrowsException<SaltParseException>(() => AtHackerHashProvider.ValidatePassword(passwordHash, "MyPassword"));
    }

    [TestMethod]
    public void Library_Throws_Value_Cannot_BeNull_Exception()
    {
        //An Exception: ValueCannotBeNullException Should Be Thrown when there is a null value passed to  as arguments to required parameters during required Operations
        //This is an exception thrown throughout the library
        Assert.ThrowsException<ValueCannotBeNullException>(() => AtHackerHashProvider.GenerateHash(""));
        Assert.ThrowsException<ValueCannotBeNullException>(() => AtHackerHashProvider.GenerateHash("MyPassword", "", true));
        Assert.ThrowsException<ValueCannotBeNullException>(() => AtHackerHashProvider.ValidatePassword("", "", ""));
    }

    [TestMethod]
    public void Library_Throws_Value_Argument_Exception()
    {
        var hashedPassword = AtHackerHashProvider.GenerateHash("MyPassword","SHA512",false);
        Console.WriteLine(hashedPassword);
        var salt = hashedPassword.Substring(1, (hashedPassword.IndexOf("@") - 1));
        Console.WriteLine(salt);
        hashedPassword = hashedPassword.Replace(salt,"");
        Console.WriteLine(hashedPassword);
        
        Assert.ThrowsException<ArgumentException>(() => AtHackerHashProvider.ValidatePassword("MyPassword",hashedPassword,"SHA512"));
    }
}
