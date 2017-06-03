using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Internal;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Microsoft.PowerShell.Commands
{
    /// <summary>
    /// Class comment
    /// </summary>
    [Cmdlet(VerbsData.ConvertFrom, "SddlString", HelpUri = "https://go.microsoft.com/fwlink/?LinkId=623636", RemotingCapability = RemotingCapability.None)]
    public sealed class ConvertFromSddlStringCommand : PSCmdlet
    {
        /// <summary>
        /// The string representing the security descriptor in SDDL syntax
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        public string Sddl { get; set; }

        /// <summary>
        /// The type of rights that this SDDL string represents, if any.
        /// </summary>
        [Parameter()]
        [ValidateSet(
            "FileSystemRights", "RegistryRights", "ActiveDirectoryRights",
            "MutexRights", "SemaphoreRights", "CryptoKeyRights",
            "EventWaitHandleRights")]
        public string Type { get; set; }

        /// <summary>
        /// Implements the BeginProcessing method for the ConvertFrom-SddlString command.
        /// </summary>
        protected override void BeginProcessing()
        {
#if CORECLR
            if (Type == "CryptoKeyRights" || Type == "ActiveDirectoryRights")
            {
                string errorMessage = StringUtil.Format(UtilityResources.TypeNotSupported, Type);
                ErrorRecord errorRecord = new ErrorRecord(
                    new ArgumentException(errorMessage),
                    "TypeNotSupported",
                    ErrorCategory.InvalidArgument,
                    null);

                ThrowTerminatingError(errorRecord);
            }
#endif
        }

        /// <summary>
        /// Implements the ProcessRecord method for the ConvertFrom-SddlString command.
        /// </summary>
        protected override void ProcessRecord()
        {
            CommonSecurityDescriptor rawSecurityDescriptor = new CommonSecurityDescriptor(false, false, Sddl);

            string owner = ConvertToNtAccount(rawSecurityDescriptor.Owner); 
            string group = ConvertToNtAccount(rawSecurityDescriptor.Group);
            List<string> discretionaryAcl = ConvertToAceString(rawSecurityDescriptor.DiscretionaryAcl, Type);
            List<string> systemAcl = ConvertToAceString(rawSecurityDescriptor.SystemAcl, Type);

            PSObject result = new PSObject();

            result.Properties.Add(new PSNoteProperty("Owner", owner));
            result.Properties.Add(new PSNoteProperty("Group", group));
            result.Properties.Add(new PSNoteProperty("DiscretionaryAcl", discretionaryAcl));
            result.Properties.Add(new PSNoteProperty("SystemAcl", systemAcl));

            WriteObject(result);
        }

        /// <summary>
        /// Translates a SID into a NT Account
        /// </summary>
        private string ConvertToNtAccount(SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).ToString();
            }
            catch {}

            return null;
        }

        /// <summary>
        /// Gets the access rights that apply to an access mask, preferring right types
        /// of 'Type' if specified.
        /// </summary>
        private List<string> GetAccessRights(long accessMask, string type)
        {
            IDictionary<string, Type> rightTypes = new Dictionary<string, Type>
            {
                { "FileSystemRights", typeof(System.Security.AccessControl.FileSystemRights) },
                { "RegistryRights", typeof(System.Security.AccessControl.RegistryRights) },
#if !CORECLR
                { "ActiveDirectoryRights", typeof(System.DirectoryServices.ActiveDirectoryRights) },
#endif
                { "MutexRights", typeof(System.Security.AccessControl.MutexRights) },
                { "SemaphoreRights", typeof(System.Security.AccessControl.SemaphoreRights) },
#if !CORECLR
                { "CryptoKeyRights", typeof(System.Security.AccessControl.CryptoKeyRights) },
#endif
                { "EventWaitHandleRights", typeof(System.Security.AccessControl.EventWaitHandleRights) }
            };

            List<Type> typesToExamine = rightTypes.Values.ToList();
            
            // If they know the access mask represents a certain type, prefer its names
            // (i.e.: CreateLink for the registry over CreateDirectories for the filesystem)
            if (!String.IsNullOrEmpty(type))
            {
                typesToExamine.Insert(0, rightTypes[type]);
            }
            
            // Stores the access types we've found that apply
            List<string> foundAccess = new List<string>();

            // Store the access types we've already seen, so that we don't report access
            // flags that are essentially duplicate. Many of the access values in the different
            // enumerations have the same value but with different names.
            HashSet<long> foundValues = new HashSet<long>();

            // Go through the entries in the different right types, and see if they apply to the
            // provided access mask. If they do, then add that to the result.
            foreach (var rightType in typesToExamine)
            {
                foreach (var accessFlag in Enum.GetNames(rightType))
                {
                    long longKeyValue = (long)Enum.Parse(rightType, accessFlag);
                    if (!foundValues.Contains(longKeyValue))
                    {
                        foundValues.Add(longKeyValue);
                        if ((accessMask & longKeyValue) == longKeyValue)
                        {
                            foundAccess.Add(accessFlag);
                        }
                    }
                }
            }

            foundAccess.Sort();

            return foundAccess;
        }

        /// <summary>
        /// Converts an ACE into a string representation
        /// </summary>
        private List<string> ConvertToAceString(CommonAcl acl, string type)
        {
            List<string> aceStrings = new List<string>();

            foreach (var ace in acl.OfType<KnownAce>())
            {
                string aceString = ConvertToNtAccount(ace.SecurityIdentifier) + ": ";

                if (ace is QualifiedAce qualifiedAce)
                {
                    aceString += qualifiedAce.AceQualifier;
                }

                if (ace.AceFlags != AceFlags.None)
                {
                    aceString += " " + ace.AceFlags;
                }

                if (ace.AccessMask != default(int))
                {
                    List<string> foundAccess = GetAccessRights(ace.AccessMask, type);

                    if (foundAccess.Count > 0)
                    {
                        aceString += $" ({string.Join(", ", foundAccess)})";
                    }
                }

                aceStrings.Add(aceString);
            }

            return aceStrings;
        }
    }
}