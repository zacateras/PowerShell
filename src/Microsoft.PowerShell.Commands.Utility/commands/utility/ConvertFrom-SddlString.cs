using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Internal;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Microsoft.PowerShell.Commands
{
    /// <summary>
    /// Class comment
    /// </summary>
    [Cmdlet(VerbsData.ConvertFrom, "SddlString", HelpUri = "https://go.microsoft.com/fwlink/?LinkId=623636", RemotingCapability = RemotingCapability.None)]
    [OutputType(typeof(SddlStringInfo))]
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
            "MutexRights", "SemaphoreRights",
#if !CORECLR
            "CryptoKeyRights",
#endif
            "EventWaitHandleRights")]
        public string Type { get; set; }

        /// <summary>
        /// Implements the ProcessRecord method for the ConvertFrom-SddlString command.
        /// </summary>
        protected override void ProcessRecord()
        {
            CommonSecurityDescriptor rawDescriptor = new CommonSecurityDescriptor(false, false, Sddl);

            SddlStringInfo result = new SddlStringInfo
            {
                Owner = ConvertToNtAccount(rawDescriptor.Owner),
                Group = ConvertToNtAccount(rawDescriptor.Group),
                DiscretionaryAcl = ConvertToAceString(rawDescriptor.DiscretionaryAcl, Type),
                SystemAcl = ConvertToAceString(rawDescriptor.SystemAcl, Type),
                RawDescriptor = rawDescriptor
            };

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
                { "ActiveDirectoryRights", typeof(System.DirectoryServices.ActiveDirectoryRights) },
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
        /// Converts an ACL into a string representation
        /// </summary>
        private List<string> ConvertToAceString(CommonAcl acl, string type)
        {
            List<string> aceStrings = new List<string>();
            StringBuilder aceSb = new StringBuilder();

            foreach (var ace in acl.OfType<KnownAce>())
            {
                aceSb.Append(ConvertToNtAccount(ace.SecurityIdentifier));
                aceSb.Append(": ");

                if (ace is QualifiedAce qualifiedAce)
                {
                    aceSb.Append(qualifiedAce.AceQualifier.ToString());
                }

                if (ace.AceFlags != AceFlags.None)
                {
                    aceSb.Append(" ");
                    aceSb.Append(ace.AceFlags.ToString());
                }

                if (ace.AccessMask != default(int))
                {
                    List<string> foundAccess = GetAccessRights(ace.AccessMask, type);

                    if (foundAccess.Count > 0)
                    {
                        aceSb.Append($" ({string.Join(", ", foundAccess)})");
                    }
                }

                aceStrings.Add(aceSb.ToString());
                aceSb.Clear();
            }

            return aceStrings;
        }
    }

    /// <summary>
    /// Holds descriptive information for SDDL string
    /// </summary>
    public class SddlStringInfo
    {
        /// <summary>
        /// Owner's account name
        public string Owner { get; set; }

        /// <summary>
        /// Owner's primary group name
        /// </summary>
        public string Group { get; set; }

        /// <summary>
        /// DACL string representation
        /// </summery>
        public List<string> DiscretionaryAcl { get; set; }

        /// <summary>
        /// SACL string representation
        /// </summery>
        public List<string> SystemAcl { get; set; }

        /// <summary>
        /// Raw security descriptor
        /// </summery>
        public CommonSecurityDescriptor RawDescriptor { get; set; }
    }
}
