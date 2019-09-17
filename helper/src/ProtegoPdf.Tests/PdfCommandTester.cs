/**
 * Copyright (C) 2018 Bernardo Balvanera
 *
 * This file is part of ProtegoPdf.
 *
 * ProtegoPdf is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

using Microsoft.VisualStudio.TestTools.UnitTesting;
using ProtegoPdf.Service;
using System.IO;
using System.Threading.Tasks;

namespace ProtegoPdf.Tests
{
    public class PdfCommandTester
    {
        public static PdfCommand GetSubject() => new PdfCommand();

        [TestClass]
        public class When_IsPdfDocument_is_called
        {

            [TestMethod]
            public async Task Should_return_OperationResult_When_called()
            {
                var subject = GetSubject();

                var result = await subject.IsPdfDocument(new PdfOptions { Source = "file.pdf" }); // any file works

                Assert.IsInstanceOfType(result, typeof(OperationResult));
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.clear.pdf")]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.3.encrypted[test][test1].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_Success_If_PDFDocument(string f)
            {
                var subject = GetSubject();

                var result = await subject.IsPdfDocument(new PdfOptions { Source = f });

                Assert.IsTrue(result.Success);
                Assert.IsTrue(result.Result);
                Assert.IsNull(result.ErrorType);
            }

            [DataTestMethod]
            [DataRow(null)]
            [DataRow("")]
            [DataRow("gasdfas;rj")]
            [DataRow("TestData/not-exists.pdf")]
            [DataRow("1")]
            public async Task Should_return_InvalidArgument_If_illegal_file_name(string f)
            {
                var subject = GetSubject();

                var result = await subject.IsPdfDocument(new PdfOptions { Source = f });

                Assert.AreEqual("Invalid_Argument", result.ErrorType);
                Assert.IsFalse(result.Success);
                Assert.IsNull(result.Result);
            }

            [DataTestMethod]
            [DataRow("TestData/invalid.pdf")]
            [DataRow("TestData/test.corrupted.pdf")]
            [DataRow("TestData/test.v1.5.corrupted.pdf")]
            [DataRow("TestData/test.v1.5.invalid.pdf")]
            public async Task Should_return_Success_If_invalid_file(string f)
            {
                // if the file is invalid, it should return false to IsPdfDocument
                // but no exceptions should be thrown
                var subject = GetSubject();

                var result = await subject.IsPdfDocument(new PdfOptions { Source = f });

                Assert.IsTrue(result.Success);
                Assert.IsFalse(result.Result);
                Assert.IsNull(result.ErrorType);
            }

            [TestMethod]
            public async Task Should_return_FileAccessError_If_file_is_blocked()
            {
                string f = "TestData/test.v1.5.clear.pdf";

                using (var blocker = File.Open(f, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var subject = GetSubject();

                    var result = await subject.IsPdfDocument(new PdfOptions { Source = f });

                    Assert.AreEqual("File_Access_Error", result.ErrorType);
                    Assert.IsFalse(result.Success);
                    Assert.IsNull(result.Result);
                }
            }

            [TestMethod]
            [Description("Make this test work by denying all permissions at the OS level for this file")]
            [Ignore]
            public async Task Should_return_InsufficientPermissions_If_file_is_inaccessible()
            {
                string f = "TestData/test.v1.6.permission.denied.pdf";

                var subject = GetSubject();

                var result = await subject.IsPdfDocument(new PdfOptions { Source = f });

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Insufficient_Permissions", result.ErrorType);
            }
        }

        [TestClass]
        public class When_IsProtected_is_called
        {
            [TestMethod]
            public async Task Should_return_OperationResult_Type_If_called()
            {
                var subject = GetSubject();

                var result = await subject.IsProtected(new PdfOptions { Source = "file.pdf" });

                Assert.IsInstanceOfType(result, typeof(OperationResult));
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.3.encrypted[test][test1].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_Success_If_file_is_protected(string f)
            {
                var subject = GetSubject();

                var result = await subject.IsProtected(new PdfOptions { Source = f });

                Assert.IsTrue(result.Success);
                Assert.IsTrue(result.Result);
                Assert.IsNull(result.ErrorType);
            }

            [DataTestMethod]
            [DataRow(null)]
            [DataRow("")]
            [DataRow("gasdfas;rj")]
            [DataRow(@"\:text.txt")]
            [DataRow("TestData/not-exists.pdf")]
            [DataRow("1")]
            public async Task Should_return_InvalidArgument_If_illegal_file_name(string f)
            {
                var subject = GetSubject();

                var result = await subject.IsProtected(new PdfOptions { Source = f });

                Assert.AreEqual("Invalid_Argument", result.ErrorType);
                Assert.IsFalse(result.Success);
                Assert.IsNull(result.Result);
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.5.corrupted.pdf")]
            [DataRow("TestData/test.v1.5.invalid.pdf")]
            public async Task Should_return_False_If_file_is_corrupted_or_not_a_pdf(string f)
            {
                var subject = GetSubject();

                var result = await subject.IsProtected(new PdfOptions { Source = f });

                Assert.IsFalse(result.Success);
                Assert.IsNull(result.Result);
                Assert.AreEqual("Not_A_Pdf_Document", result.ErrorType);
            }

            [TestMethod]
            public async Task Should_return_FileAccessError_If_file_is_blocked()
            {
                string f = "TestData/test.v1.4.clear.pdf";
                using (var blocker = File.Open(f, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var subject = GetSubject();

                    var result = await subject.IsProtected(new PdfOptions { Source = f });

                    Assert.AreEqual("File_Access_Error", result.ErrorType);
                    Assert.IsFalse(result.Success);
                    Assert.IsNull(result.Result);
                }
            }

            [TestMethod]
            [Ignore]
            [Description("Make this test work by denying all permissions at the OS level for this file")]
            public async Task Should_return_InsufficientPermissions_If_file_is_inaccessible()
            {
                string f = "TestData/test.v1.6.permission.denied.pdf";

                var subject = GetSubject();

                var result = await subject.IsProtected(new PdfOptions { Source = f });

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Insufficient_Permissions", result.ErrorType);
            }
        }

        [TestClass]
        public class When_protecting_a_file
        {
            [DataTestMethod]
            [DataRow("TestData/test.v1.2.clear.pdf")]
            [DataRow("TestData/test.v1.3.clear.pdf")]
            [DataRow("TestData/test.v1.3.clear2.pdf")]
            [DataRow("TestData/test.v1.4.clear.pdf")]
            [DataRow("TestData/test.v1.5.clear.pdf")]
            [DataRow("TestData/test.v1.6.clear.pdf")]
            public async Task Should_return_Success_If_valid_file(string sourceFile)
            {
                var targetFile = $"{sourceFile}.encrypted.pdf";
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    UserPassword = "hello!",
                    Permissions = 0xf3c // all permissions granted
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);

                Assert.IsTrue(result.Success);
                Assert.IsTrue(File.Exists(targetFile));

                result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                Assert.IsTrue(result.Success);
                Assert.IsTrue(result.Result);
                File.Delete(targetFile);
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.clear.pdf")]
            [DataRow("TestData/test.v1.3.clear.pdf")]
            [DataRow("TestData/test.v1.4.clear.pdf")]
            [DataRow("TestData/test.v1.5.clear.pdf")]
            [DataRow("TestData/test.v1.6.clear.pdf")]
            public async Task Should_protect_If_file_is_unprotected(string sourceFile)
            {
                var targetFile = $"{sourceFile}.encrypted.pdf";
                try
                {
                    File.Copy(sourceFile, targetFile, true); // source is a clean file, copy it and avoid overwriting original one
                    var request = new PdfOptions
                    {
                        Source = targetFile,
                        Target = targetFile,
                        UserPassword = "hello!"
                    };
                    var subject = GetSubject();
                    var result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsFalse(result.Result); // make sure to start with an unprotected file.

                    result = await subject.Protect(request);

                    Assert.IsTrue(result.Success);
                    Assert.IsTrue(File.Exists(targetFile));

                    result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsTrue(result.Success);
                    Assert.IsTrue(result.Result);
                }
                finally
                {
                    if (File.Exists(targetFile))
                        File.Delete(targetFile);
                }
            }

            [TestMethod]
            public async Task Should_return_InsufficientPermissions_If_path_is_protected_or_inaccessible()
            {
                var sourceFile = "TestData/test.v1.2.clear.pdf";
                var targetFile = "C:\\Program Files\\mytestfile.encrypted.pdf";

                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    UserPassword = "hello!"
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Insufficient_Permissions", result.ErrorType);
            }

            [DataTestMethod]
            [DataRow(@"D:\AppDataz\testdata.pdf")]
            [DataRow(@"P:\testdata.pdf")]
            public async Task Should_return_InvalidArgument_If_illegal_file_name(string targetFile)
            {
                var sourceFile = "TestData/test.v1.2.clear.pdf";


                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    UserPassword = "hello!"
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Invalid_Argument", result.ErrorType);
            }

            [DataTestMethod]
            [DataRow(@":\text.txt")]
            [DataRow(@":text.txt")]
            public async Task Should_return_InvalidArgument_If_illegal_save_file_name(string targetFile)
            {
                var sourceFile = "TestData/test.v1.2.clear.pdf";

                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    UserPassword = "hello!"
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Invalid_Argument", result.ErrorType);
            }

            [TestMethod]
            public async Task Should_return_FileAccessError_If_file_is_blocked()
            {
                var sourceFile = "TestData/test.v1.2.clear.pdf";
                var targetFile = $"{sourceFile}.encrypted.pdf";
                try
                {
                    File.Copy(sourceFile, targetFile, true); // source is a clean file, copy it and avoid overwriting original one
                    var request = new PdfOptions
                    {
                        Source = targetFile,
                        Target = targetFile,
                        UserPassword = "hello!"
                    };
                    var subject = GetSubject();
                    var result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsFalse(result.Result); // make sure to start with an unprotected file.

                    using (var blocker = File.Open(targetFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    {
                        result = await subject.Protect(request);

                        Assert.IsFalse(result.Success);
                        Assert.AreEqual("File_Access_Error", result.ErrorType);
                    }
                }
                finally
                {
                    if (File.Exists(targetFile))
                        File.Delete(targetFile);
                }
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.3.encrypted[test][test1].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_BadPassword_If_already_protected(string sourceFile)
            {
                var targetFile = $"{sourceFile}.encrypted.pdf";
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    UserPassword = "badpassword"
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);
                Assert.IsFalse(result.Success);
                Assert.AreEqual("Bad_Password", result.ErrorType);
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.3.encrypted[test][test1].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][].pdf")]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_BadPassword_If_invalid_password(string sourceFile)
            {
                var targetFile = $"{sourceFile}.encrypted.pdf";
                try
                {
                    File.Copy(sourceFile, targetFile, true); // source is a clean file, copy it and avoid overwriting original one
                    var request = new PdfOptions
                    {
                        Source = targetFile,
                        Target = targetFile,
                        UserPassword = "hello!" // actual password is `test`
                    };
                    var subject = GetSubject();

                    var result = await subject.Protect(request);

                    Assert.IsFalse(result.Success);
                    Assert.AreEqual("Bad_Password", result.ErrorType);
                }
                finally
                {
                    if (File.Exists(targetFile))
                        File.Delete(targetFile);
                }
            }

            [TestMethod]
            public async Task Should_not_leave_file_blocked_If_errored()
            {
                var sourceFile = "TestData/test.v1.5.encrypted[test].pdf";
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    UserPassword = "hello!"
                };
                var subject = GetSubject();


                var prot = await subject.Protect(request);


                Assert.IsFalse(prot.Success, "Should have fail at protect");
                Assert.AreEqual("Bad_Password", prot.ErrorType);

                // files should not be blocked and by calling IsPdfDocument,
                // the proper condition will be triggered
                var result = await subject.IsPdfDocument(new PdfOptions { Source = sourceFile });

                Assert.AreNotEqual("File_Access_Error", result.ErrorType);
            }

            [TestMethod]
            [Ignore]
            [Description("Make this test work by denying all permissions at the OS level for this file")]
            public async Task Should_return_InsufficientPermissions_If_file_is_inaccessible()
            {
                string f = "TestData/test.v1.6.permission.denied.pdf";
                var request = new PdfOptions
                {
                    Source = f,
                    Target = f,
                    UserPassword = "hello!"
                };
                var subject = GetSubject();

                var result = await subject.Protect(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Insufficient_Permissions", result.ErrorType);
            }
        }

        [TestClass]
        public class When_unlocking_file
        {
            [DataTestMethod]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            public async Task Should_succeed_If_password_is_valid(string sourceFile)
            {
                var targetFile = $"{sourceFile}.unlocked.pdf";
                try
                {
                    File.Copy(sourceFile, targetFile, true); // source is a clean file, copy it and avoid overwriting original one
                    var request = new PdfOptions
                    {
                        Source   = targetFile,
                        Target   = targetFile,
                        Password = "test"
                    };

                    var subject = GetSubject();
                    var result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsTrue(result.Result); // make sure to start with a protected file.

                    result = await subject.Unlock(request);

                    Assert.IsTrue(result.Success);
                    Assert.IsTrue(File.Exists(targetFile));

                    result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsTrue(result.Success);
                    Assert.IsFalse(result.Result);
                }
                finally
                {
                    if (File.Exists(targetFile))
                        File.Delete(targetFile);
                }
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.2.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.4.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.5.encrypted[test].pdf")]
            [DataRow("TestData/test.v1.6.encrypted[][test].pdf")]
            public async Task Should_return_BadPassword_If_invalid_password(string sourceFile)
            {
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "wrong_password"
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Bad_Password", result.ErrorType);
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_BadOwnerPassword_If_invalid_owner_password(string sourceFile)
            {
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "test" // correct user password, incorrect owner password.
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Bad_Owner_Password", result.ErrorType);
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_succeed_If_only_userpassword_is_provided_but_forced(string sourceFile)
            {
                var targetFile = $"{sourceFile}.unlocked.pdf";
                try
                {
                    File.Copy(sourceFile, targetFile, true); // source is a clean file, copy it and avoid overwriting original one
                    var request = new PdfOptions
                    {
                        Source = targetFile,
                        Target = targetFile,
                        Password = "test", //usign user password instead of owner password
                        ForceDecryption = true
                    };

                    var subject = GetSubject();
                    var result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsTrue(result.Result); // make sure to start with a protected file.

                    result = await subject.Unlock(request);

                    Assert.IsTrue(result.Success);
                    Assert.IsTrue(File.Exists(targetFile));

                    result = await subject.IsProtected(new PdfOptions { Source = targetFile });
                    Assert.IsTrue(result.Success);
                    Assert.IsFalse(result.Result);
                }
                finally
                {
                    if (File.Exists(targetFile))
                        File.Delete(targetFile);
                }
            }

            [DataTestMethod]
            [DataRow("TestData/test.v1.6.restricted[owner][test].pdf")]
            public async Task Should_return_BadPassword_If_invalid_password_even_if_forced(string sourceFile)
            {
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "incorrect_user_password",
                    ForceDecryption = true
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Bad_Password", result.ErrorType);
            }

            [TestMethod]
            [DataRow("TestData/invalid.pdf")]
            [DataRow("TestData/test.corrupted.pdf")]
            public async Task Should_return_InvalidArgument_If_invalid_file(string sourceFile)
            {
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "test"
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Invalid_Argument", result.ErrorType);
            }

            [TestMethod]
            public async Task Should_not_leave_file_blocked_If_errored()
            {
                var sourceFile = "TestData/test.v1.5.encrypted[test].pdf";
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "Hello!"
                };
                var subject = GetSubject();


                var prot = await subject.Unlock(request);

                Assert.IsFalse(prot.Success);
                Assert.AreEqual("Bad_Password", prot.ErrorType);

                // files should not be blocked and by calling IsPdfDocument,
                // the proper condition will be triggered
                var result = await subject.IsPdfDocument(new PdfOptions { Source = sourceFile });

                Assert.AreNotEqual("File_Access_Error", result.ErrorType);
            }

            [TestMethod]
            [DataRow("TestData/test.v1.2.clear.pdf")]
            [DataRow("TestData/test.v1.3.clear.pdf")]
            [DataRow("TestData/test.v1.4.clear.pdf")]
            [DataRow("TestData/test.v1.5.clear.pdf")]
            [DataRow("TestData/test.v1.6.clear.pdf")]
            public async Task Should_succeed_If_not_protected(string sourceFile)
            {
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "Hello!"
                };
                var subject = GetSubject();


                var prot = await subject.Unlock(request);

                Assert.IsTrue(prot.Success);    
            }

            [TestMethod]
            public async Task Should_return_GeneralError_If_unable_to_read_file()
            {
                var sourceFile = "TestData/test.v1.6.attachement-encrypted.pdf"; // this file is corrupted or simply, iText can't read from it when other pdf readers can.
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "test"
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("General_Error", result.ErrorType);
            }

            [TestMethod]
            public async Task Should_return_InsufficientPermissions_If_path_is_inaccessible()
            {
                var sourceFile = "TestData/test.v1.2.clear.pdf";
                var targetFile = "C:\\Program Files\\mytestfile.encrypted.pdf";

                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = targetFile,
                    Password = "Hello!"
                };
                var subject = GetSubject();

                var result = await subject.Unlock(request);

                Assert.IsFalse(result.Success);
                Assert.AreEqual("Insufficient_Permissions", result.ErrorType);
            }

            [TestMethod]
            public async Task Should_return_FileAccessError_If_file_is_blocked()
            {
                var sourceFile = "TestData/test.v1.5.encrypted[test].pdf";
                var request = new PdfOptions
                {
                    Source = sourceFile,
                    Target = sourceFile,
                    Password = "hello!"
                };
                var subject = GetSubject();

                using (var blocker = File.Open(sourceFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    var result = await subject.Unlock(request); 

                    Assert.IsFalse(result.Success);
                    Assert.AreEqual("File_Access_Error", result.ErrorType);
                }
            }
        }
    }
}
