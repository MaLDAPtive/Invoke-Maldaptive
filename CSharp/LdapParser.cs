// This file is part of the MaLDAPtive framework.
//
// Copyright 2024 Sabajete Elezaj (aka Sabi) <@sabi_elezi>
// 	while at Solaris SE <https://solarisgroup.com/>
// 	and Daniel Bohannon (aka DBO) <@danielhbohannon>
// 	while at Permiso Security <https://permiso.io/>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



namespace Maldaptive
{
	/// <summary>
    /// This namespace parses LDAP SearchFilters according to this spec:
	/// https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
    /// </summary>

    using System;
    using System.Text.RegularExpressions;
    using System.Collections;
    using System.Collections.Generic;
    using System.Text;
    using System.Linq;

    /// <summary>
    /// This class defines token object for minimally tokenized LDAP SearchFilter.
	/// </summary>
    public class LdapParserException : Exception
    {
        // Constructor that takes two arguments.
		public LdapParserException(string fileName, string message) : base(message)
		{
			FileName = fileName;
		}

		// Auto-implemented readonly properties.
		public string FileName { get; }

		// Method that overrides the base class (System.Object) implementation.
		public override string ToString()
		{
			return $"LDAP Parsing Exception: {FileName} - {Message}";
		}
	}

    /// <summary>
    /// This class defines token object for minimally tokenized LDAP SearchFilter.
	/// </summary>
    public class LdapToken
    {
        // Constructor that takes no arguments.
        public LdapToken()
        {
            Content = null;
            Type = LdapTokenType.Undefined;
            SubType = null;
            Start = -1;
            Length = -1;
            Depth = -1;
            TokenList = new List<LdapToken>();
        }

        // Constructor that takes four arguments.
        public LdapToken(string content, LdapTokenType type, int start, int depth)
        {
            Content = content;
            Type = type;
            SubType = null;
            Start = start;
            Length = content.Length;
            Depth = depth;
            TokenList = new List<LdapToken>();
        }

        // Constructor that takes five arguments.
        public LdapToken(string content, LdapTokenType type, LdapTokenSubType subType, int start, int depth)
        {
            Content = content;
            Type = type;
            SubType = subType;
            Start = start;
            Length = content.Length;
            Depth = depth;
            TokenList = new List<LdapToken>();
        }

        // Constructor that takes five arguments.
        public LdapToken(string content, List<LdapToken> contentList, LdapTokenType type, int start, int depth)
        {
            Content = content;
            Type = type;
            SubType = null;
            Start = start;
            Length = content.Length;
            Depth = depth;
            TokenList = contentList;
        }

        // Auto-implemented readonly properties.
        public string Content { get; set; }
        public LdapTokenType Type { get; set; }
        public Nullable<LdapTokenSubType> SubType { get; set; }
        public int Start { get; set; }
        public int Length { get; set; }
        public int Depth { get; set; }
        public List<LdapToken> TokenList { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            //return Content;
            return $"Depth: {Depth}, Length: {Length}, Type: {Type}, SubType: {SubType}, Content: {Content}";
        }
    }

    /// <summary>
    /// This class defines token object for deeply enriched tokenized LDAP SearchFilter.
	/// </summary>
    public class LdapTokenEnriched : LdapToken
    {
        // Constructor that takes LdapToken as an argument to copy over corresponding properties
		// into new LdapTokenEnriched object.
		public LdapTokenEnriched(LdapToken ldapToken)
        {
			// Define string for potential decoded version of Content property, initialized to
			// Content property if not eligible for decoding.
			string ldapTokenContentDecoded = ldapToken.Content;

			// Retrieve LdapContext object for input LdapToken based on its Type.
			// At a minimum, LdapContext object will be used to populate ContentDecoded property.
			// If LdapToken is part of a DN Attribute Value (i.e. its SubType is RDN) then decode
			// any potential hex encoding to accurately retrieve LdapContext object.
			LdapContext ldapTokenContext;
            if (ldapToken.SubType == LdapTokenSubType.RDN)
            {
				// Since LdapToken is an RDN, set Boolean so DN-specific logic is applied in
				// GetTokenContext method invocation.
				bool isDn = true;

                 // Remove potential hex encoding in original Content property and update
				 // ldapTokenContentDecoded string.
                ldapTokenContentDecoded = string.Concat(LdapParser.ParseLdapValue(ldapToken.Content, true).Select(token => token.ContentDecoded));

				// Temporarily override Content property with decoded value above and then revert back
				// to original Content property after GetTokenContext method invocation is complete.
				// This will allow a hex encoded RDN Attribute name (e.g. '\44\43') to be temporarily
				// changed to its decoded version (e.g. 'dc') for an accurate lookup in GetTokenContext.
				string ldapTokenContent = ldapToken.Content;
				ldapToken.Content = ldapTokenContentDecoded;
                ldapTokenContext = GetTokenContext(ldapToken, isDn);
                ldapToken.Content = ldapTokenContent;
			}
			else
			{
                // If LdapToken is a DN Attribute Value (i.e. LdapToken's TokenList property is
				// populated with RDN LdapTokens) then set Boolean so DN-specific logic is applied
				// in GetTokenContext method invocation.
                bool isDn = (ldapToken.TokenList.Count > 0 && ldapToken.Type == LdapTokenType.Value) ? true : false;

                ldapTokenContext = GetTokenContext(ldapToken, isDn);
            }

			// If LdapContext object was retrieved above then extract decoded value for final
			// ContentDecoded property.
			if (ldapTokenContext != null)
			{
				switch (ldapToken.Type)
				{
					case LdapTokenType.Attribute:
						// Update ContentDecoded property with normalized Attribute name from
						// Attribute Context object if it exists.
						ldapTokenContentDecoded = (ldapTokenContext.Attribute.Name == "Undefined") ? ldapTokenContentDecoded : ldapTokenContext.Attribute.Name;
						break;
					case LdapTokenType.ExtensibleMatchFilter:
						// Update ContentDecoded property with ExtensibleMatchFilter OID from
						// ExtensibleMatchFilter Context object if it exists, updating with OID
						// instead of Name since OID syntax ExtensibleMatchFilter is properly
						// interpreted by LDAP but Name syntax is not.
						ldapTokenContentDecoded = (ldapTokenContext.ExtensibleMatchFilter.OID == "Undefined") ? ldapTokenContentDecoded : $":{ldapTokenContext.ExtensibleMatchFilter.OID}:";
						break;
					case LdapTokenType.Value:
						ldapTokenContentDecoded = ldapTokenContext.Value.ContentDecoded;
						break;
				}
			}

			// If Whitespace LdapToken then replace hex-encoded Whitespace with whitespace character.
			if (ldapToken.Type == LdapTokenType.Whitespace && ldapToken.SubType == LdapTokenSubType.RDN)
			{
				ldapTokenContentDecoded = ldapToken.Content.Replace(@"\20", " ");
			}

            Content = ldapToken.Content;
			ContentDecoded = ldapTokenContentDecoded;
			Format = GetTokenFormat(ldapToken);
			IsDefined = ((ldapToken.Type == LdapTokenType.Attribute) || (ldapToken.Type == LdapTokenType.ExtensibleMatchFilter)) ? (bool?)((bool)IsLdapTokenDefined(ldapTokenContext,ldapToken.Type)) : null;
            Type = ldapToken.Type;
            TypeBefore = null;
            TypeAfter = null;
            SubType = ldapToken.SubType != null ? ldapToken.SubType : null;
            Start = ldapToken.Start;
            Length = ldapToken.Length;
            Depth = ldapToken.Depth;
            ScopeSyntax = null;
            ScopeApplication = null;
			Context = ldapTokenContext;
            // Convert TokenList from List<LdapToken> to List<LdapTokenEnriched> in recursive
			// constructor invocation.
            TokenList = ldapToken.TokenList.ConvertAll(token => new LdapTokenEnriched(token));
            Guid = null;
        }

        // Constructor that takes LdapTokenEnriched as an argument to copy over corresponding
		// properties into new LdapTokenEnriched object.
        public LdapTokenEnriched(LdapTokenEnriched ldapTokenEnriched)
        {
            Content = ldapTokenEnriched.Content;
            ContentDecoded = ldapTokenEnriched.ContentDecoded;
			Format = ldapTokenEnriched.Format;
			IsDefined = ldapTokenEnriched.IsDefined;
            Type = ldapTokenEnriched.Type;
            TypeBefore = ldapTokenEnriched.TypeBefore;
            TypeAfter = ldapTokenEnriched.TypeAfter;
            SubType = ldapTokenEnriched.SubType != null ? ldapTokenEnriched.SubType : null;
            Start = ldapTokenEnriched.Start;
            Length = ldapTokenEnriched.Length;
            Depth = ldapTokenEnriched.Depth;
            ScopeSyntax = ldapTokenEnriched.ScopeSyntax;
            ScopeApplication = ldapTokenEnriched.ScopeApplication;
			Context = ldapTokenEnriched.Context;
            TokenList = ldapTokenEnriched.TokenList;
            Guid = ldapTokenEnriched.Guid;
        }

        // Auto-implemented readonly properties.
		public LdapTokenFormat Format { get; set; }
		public Nullable<bool> IsDefined { get; set; }
        public Nullable<LdapTokenType> TypeBefore { get; set; }
        public Nullable<LdapTokenType> TypeAfter { get; set; }
        public Nullable<LdapTokenScope> ScopeSyntax { get; set; }
        public Nullable<LdapTokenScope> ScopeApplication { get; set; }
		public LdapContext Context { get; set; }
        public new List<LdapTokenEnriched> TokenList { get; set; }
        public Nullable<Guid> Guid { get; set; }
		public string ContentDecoded { get; set; }

		/// <summary>
		/// This helper method validates if input LDAP Context object describes an LdapToken with a
		// defined Content value.
		/// </summary>
        private static bool IsLdapTokenDefined(LdapContext ldapContext, LdapTokenType ldapTokenType)
        {
			// Set default bool to false if input LdapToken's Content cannot be confirmed as defined
			// throughout current method.
			bool isDefined = false;

            // Return current bool if input ldapContext is null or empty.
			if (ldapContext == null)
            {
                return isDefined;
            }

			// Perform format identification logic based on input LdapToken's Type property.
			switch (ldapTokenType)
			{
				case LdapTokenType.Attribute:
					isDefined = (ldapContext.Attribute.Name != "Undefined") ? true : false;
					break;
				case LdapTokenType.ExtensibleMatchFilter:
					isDefined = (ldapContext.ExtensibleMatchFilter.Name != "Undefined") ? true : false;
					break;
				case LdapTokenType.Value:
					isDefined = (ldapContext.Value.ContentParsedList.Count > 0) ? true : false;
					break;
			}

			// Return current bool indicating input LdapToken's defined status.
			return isDefined;
		}

		/// <summary>
		/// This helper method returns format of input LDAP token's Content value.
		/// </summary>
		private static LdapTokenFormat GetTokenFormat(LdapToken ldapToken)
		{
			// Set default LdapTokenFormat to Undefined if no other matching formats are
			// identified throughout current method.
			LdapTokenFormat format = LdapTokenFormat.Undefined;

            // Return current format if input ldapToken's Content property is null or empty.
			if (ldapToken.Content.Length == 0)
            {
				return format;
            }

			// Perform format identification logic based on input LdapToken's Type property.
			switch (ldapToken.Type)
			{
				case LdapTokenType.Attribute:
					format = LdapParser.IsOid(ldapToken.Content) ? LdapTokenFormat.OID : LdapTokenFormat.String;
					break;
				case LdapTokenType.ExtensibleMatchFilter:
					// Remove potential single leading/trailing colon character from
					// ExtensibleMatchFilter value before evaluating underlying value.
					format = LdapParser.IsOid(LdapParser.TrimOne(ldapToken.Content, ':')) ? LdapTokenFormat.OID : LdapTokenFormat.String;
					break;
				default:
					format = LdapTokenFormat.NA;
					break;
			}

			// Return input LdapToken's current format.
			return format;
		}

		/// <summary>
		/// This helper method returns new generic LdapContext object initialized with new specific
		/// Context object based on input LDAP token type.
		/// </summary>
        private static LdapContext GetTokenContext(LdapToken ldapToken, bool isDn = false)
        {
            // Set default LdapContext object.
            LdapContext context = new LdapContext();

			// Populate Context object based on input LdapToken's Type property.
			switch (ldapToken.Type)
			{
				case LdapTokenType.Attribute:
					context.Attribute = LdapParser.GetLdapAttribute(ldapToken.Content);
					break;
				case LdapTokenType.ExtensibleMatchFilter:
					// Remove potential single leading/trailing colon character from
					// ExtensibleMatchFilter value before evaluating underlying value.
					context.ExtensibleMatchFilter = LdapParser.GetLdapExtensibleMatchFilter(LdapParser.TrimOne(ldapToken.Content, ':'));
					break;
				case LdapTokenType.Value:
                    context.Value = LdapParser.GetLdapValue(ldapToken.Content, isDn);
                    break;
			};

			// Return input LdapToken's current Context object.
			return context;
		}

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Guid: {Guid}, Depth: {Depth}, Length: {Length}, Format: {Format}, IsDefined: {IsDefined}, Type: {Type}, SubType: {SubType}, ScopeSyntax: {ScopeSyntax}, ScopeApplication: {ScopeApplication}, Content: {Content}, ContentDecoded: {ContentDecoded}";
        }
    }

    /// <summary>
    /// This class holds placeholders for different *Context object types for simplified storage
	/// and reference in LdapTokenEnriched, LdapFilter and LdapBranch objects.
	/// </summary>
    public class LdapContext
    {
        // Constructor that takes no arguments.
        public LdapContext()
        {
			BooleanOperator = null;
			Attribute = null;
			ExtensibleMatchFilter = null;
			Value = null;
        }

        // Auto-implemented readonly properties.
        public LdapBooleanOperatorContext BooleanOperator { get; set; }
        public LdapAttributeContext Attribute { get; set; }
        public LdapExtensibleMatchFilterContext ExtensibleMatchFilter { get; set; }
        public LdapValueContext Value { get; set; }
    }

    /// <summary>
    /// This class holds full context of current and related BooleanOperator token(s) in entire LDAP SearchFilter.
	/// </summary>
    public class LdapBooleanOperatorContext
    {
        // Constructor that takes no arguments.
        public LdapBooleanOperatorContext()
        {
			LogicalFilterInclusion = false;
			LogicalFilterBooleanOperator = null;
			LogicalFilterListBooleanOperator = null;
			NegationBooleanOperatorTraversal = false;
			HistoricalBooleanOperatorCount = 0;
            FilterListBooleanOperatorDistance = -1;
            FilterListBooleanOperatorTokenListCount = 0;
            FilterListBooleanOperatorTokenList = new List<LdapTokenEnriched>();
            FilterListBooleanOperator = null;
            FilterBooleanOperatorTokenListCount = 0;
            FilterBooleanOperatorTokenList = new List<LdapTokenEnriched>();
            FilterBooleanOperator = null;
        }

        // Constructor that takes four arguments.
        public LdapBooleanOperatorContext(int depth, List<LdapTokenEnriched> filterListBooleanOperatorTokenList, List<LdapTokenEnriched> filterBooleanOperatorTokenList, int ldapTokenBooleanOperatorHistoricalCount)
        {
			LogicalFilterInclusion = ToLogicalFilterInclusion(filterListBooleanOperatorTokenList, filterBooleanOperatorTokenList);
			LogicalFilterBooleanOperator = ToLogicalFilterBooleanOperator(filterListBooleanOperatorTokenList);
			LogicalFilterListBooleanOperator = filterListBooleanOperatorTokenList.Count > 0 ? LdapParser.ToLogicalBooleanOperator(string.Concat(filterListBooleanOperatorTokenList.Select(token => token.Content))) : null;
            NegationBooleanOperatorTraversal = false;
			HistoricalBooleanOperatorCount = ldapTokenBooleanOperatorHistoricalCount;
            FilterListBooleanOperatorDistance = filterListBooleanOperatorTokenList.Count > 0 ? depth - filterListBooleanOperatorTokenList[filterListBooleanOperatorTokenList.Count - 1].Depth : 0;
            FilterListBooleanOperatorTokenListCount = filterListBooleanOperatorTokenList.Count;
            // Create copy of filterListBooleanOperatorTokenList so it is decoupled from input object.
            FilterListBooleanOperatorTokenList = filterListBooleanOperatorTokenList.Count > 0 ? filterListBooleanOperatorTokenList.ConvertAll(token => new LdapTokenEnriched(token)) : null;
            FilterListBooleanOperator = filterListBooleanOperatorTokenList.Count > 0 ? filterListBooleanOperatorTokenList[filterListBooleanOperatorTokenList.Count - 1] : null;
            FilterBooleanOperatorTokenListCount = filterBooleanOperatorTokenList.Count;
            // Create copy of filterBooleanOperatorTokenList so it is decoupled from input object.
            FilterBooleanOperatorTokenList = filterBooleanOperatorTokenList.Count > 0 ? filterBooleanOperatorTokenList.ConvertAll(token => new LdapTokenEnriched(token)) : null;
            FilterBooleanOperator = filterBooleanOperatorTokenList.Count > 0 ? filterBooleanOperatorTokenList[filterBooleanOperatorTokenList.Count - 1] : null;
        }

        // Auto-implemented readonly properties.
        public bool LogicalFilterInclusion { get; set; }
        public string LogicalFilterBooleanOperator { get; set; }
        public string LogicalFilterListBooleanOperator { get; set; }
		public bool NegationBooleanOperatorTraversal { get; set; }
		public int HistoricalBooleanOperatorCount { get; set; }
		public int FilterListBooleanOperatorDistance { get; set; }
        public int FilterListBooleanOperatorTokenListCount { get; set; }
        public List<LdapTokenEnriched> FilterListBooleanOperatorTokenList { get; set; }
        public LdapTokenEnriched FilterListBooleanOperator { get; set; }
        public int FilterBooleanOperatorTokenListCount { get; set; }
        public List<LdapTokenEnriched> FilterBooleanOperatorTokenList { get; set; }
        public LdapTokenEnriched FilterBooleanOperator { get; set; }

		/// <summary>
		/// This helper method returns logical BooleanOperator value for Filter, handling compound
		/// logical BooleanOperator scenarios.
		/// </summary>
		private static string ToLogicalFilterBooleanOperator(List<LdapTokenEnriched> filterListBooleanOperatorTokenList)
		{
            // Return null if input filterListBooleanOperatorTokenList List is null or empty.
            if (filterListBooleanOperatorTokenList.Count == 0)
            {
                return null;
            }

			// Calculate logical BooleanOperator value for BooleanOperator character(s) in input
			// filterListBooleanOperatorTokenList List.
			string logicalBooleanOperator = LdapParser.ToLogicalBooleanOperator(string.Concat(filterListBooleanOperatorTokenList.Select(token => token.Content)));

			// Invert potential compound logical BooleanOperator value.
			logicalBooleanOperator = (logicalBooleanOperator != null) ? logicalBooleanOperator.Replace("!|","&").Replace("!&","|") : logicalBooleanOperator;

			// Return final logical Filter BooleanOperator value.
			return logicalBooleanOperator;
		}

		/// <summary>
		/// This helper method returns Boolean defining if Filter is logically included or excluded
		/// in LDAP SearchFilter.
		/// </summary>
		private static bool ToLogicalFilterInclusion(List<LdapTokenEnriched> filterListBooleanOperatorTokenList, List<LdapTokenEnriched> filterBooleanOperatorTokenList)
		{
			// Calculate logical BooleanOperator value for BooleanOperator character(s) in input
			// filterListBooleanOperatorTokenList List.
			string logicalBooleanOperator = (filterListBooleanOperatorTokenList.Count > 0) ? LdapParser.ToLogicalBooleanOperator(string.Concat(filterListBooleanOperatorTokenList.Select(token => token.Content))) : "";

			// Calculate potential logical negation BooleanOperator value for BooleanOperator
			// character(s) in input filterBooleanOperatorTokenList List, handling both FilterList-scope
			// negation traversal and Filter-scope negation BooleanOperator ('!') scenarios.
			string logicalNegationBooleanOperator = ((filterBooleanOperatorTokenList.Count > 0) && (filterBooleanOperatorTokenList[0].Content == "!")) ? string.Concat(filterBooleanOperatorTokenList.Select(token => token.Content)) : "";

			// Calculate number of negation BooleanOperators.
			int negationBooleanOperatorCount = string.Concat(logicalBooleanOperator, logicalNegationBooleanOperator).Length - string.Concat(logicalBooleanOperator, logicalNegationBooleanOperator).Replace("!","").Length;

			// Return logical Filter inclusion bool based on if cumulative count of negation
			// BooleanOperator values is even or odd.
			// This works on the basis that an even number of negation BooleanOperator values
			// logically, even if not adjacent, cancel each other out.
			return ((negationBooleanOperatorCount % 2) == 0) ? true : false;
		}

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            if (FilterListBooleanOperatorTokenList.Count > 0 || FilterBooleanOperatorTokenList.Count > 0)
            {
                return $"2 LogicalFilterInclusion={LogicalFilterInclusion}, LogicalFilterBooleanOperator={LogicalFilterBooleanOperator}, LogicalFilterListBooleanOperator={LogicalFilterListBooleanOperator}, BOOLEANOPERATOR TRAVERSAL={NegationBooleanOperatorTraversal}, count={FilterListBooleanOperatorTokenListCount}_{FilterBooleanOperatorTokenListCount}, DISTANCE: {FilterListBooleanOperatorDistance}, FilterListBooleanOperator(count={FilterListBooleanOperatorTokenListCount}): {FilterListBooleanOperator}, FilterBooleanOperator(count={FilterBooleanOperatorTokenListCount}): {FilterBooleanOperator}";
            }
            else
            {
                return "";
            }
        }
    }

    /// <summary>
    /// This class holds full context of Attribute token, notably including OID representation and
	/// ValueFormat properties.
	/// </summary>
    public class LdapAttributeContext
    {
        // Constructor that takes no arguments.
        public LdapAttributeContext()
        {
			Name = "Undefined";
			OID = "Undefined";
			ValueFormat = LdapTokenFormat.Undefined;
			SyntaxID = "Undefined";
			ADSType = LdapAttributeSyntaxADSType.Undefined;
			SDSType = LdapAttributeSyntaxSDSType.Undefined;
			MAPIType = LdapAttributeSyntaxMAPIType.Undefined;
			SyntaxTitle = LdapAttributeSyntaxTitle.Undefined;
			SyntaxDescription = "Undefined";
        }

        // Constructor that takes nine arguments.
        public LdapAttributeContext(string name, string oid, LdapTokenFormat valueFormat, string syntaxID, LdapAttributeSyntaxADSType adsType, LdapAttributeSyntaxSDSType sdsType, LdapAttributeSyntaxMAPIType mapiType, LdapAttributeSyntaxTitle syntaxTitle, string syntaxDescription)
        {
			Name = name;
			OID = oid;
			ValueFormat = valueFormat;
			SyntaxID = syntaxID;
			ADSType = adsType;
			SDSType = sdsType;
			MAPIType = mapiType;
			SyntaxTitle = syntaxTitle;
			SyntaxDescription = syntaxDescription;
        }

        // Auto-implemented readonly properties.
        public string Name { get; set; }
		public string OID { get; set; }
		public LdapTokenFormat ValueFormat { get; set; }
        public string SyntaxID { get; set; }
        public LdapAttributeSyntaxADSType ADSType { get; set; }
        public LdapAttributeSyntaxSDSType SDSType { get; set; }
        public LdapAttributeSyntaxMAPIType MAPIType { get; set; }
        public LdapAttributeSyntaxTitle SyntaxTitle { get; set; }
        public string SyntaxDescription { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Name: {Name}, OID: {OID}, SyntaxID: {SyntaxID}, ADSType: {ADSType}, SDSType: {SDSType}, MAPIType: {MAPIType}, SyntaxTitle: {SyntaxTitle}, SyntaxDescription: {SyntaxDescription}";
        }
    }

    /// <summary>
    /// This class holds full context of ExtensibleMatchFilter token, notably including OID
	/// representation property.
	/// </summary>
    public class LdapExtensibleMatchFilterContext
    {
        // Constructor that takes no arguments.
        public LdapExtensibleMatchFilterContext()
        {
			Name = "Undefined";
			OID = "Undefined";
			Description = "Undefined";
        }

        // Constructor that takes three arguments.
        public LdapExtensibleMatchFilterContext(string name, string oid, string description)
		{
			Name = name;
			OID = oid;
			Description = description;
        }

        // Auto-implemented readonly properties.
        public string Name { get; set; }
		public string OID { get; set; }
        public string Description { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Name: {Name}, OID: {OID}, Description: {Description}";
        }
    }

    /// <summary>
    /// This class holds full context of Value token, notably including Format, parsed and decoded
	/// Content and Bitwise value dictionary properties.
	/// </summary>
    public class LdapValueContext
    {
        // Constructor that takes no arguments.
        public LdapValueContext()
        {
			Format = LdapTokenFormat.Undefined;
			Content = "";
			ContentDecoded = "";
			ContentParsedList = new List<LdapValueParsed>();
			BitwiseAddend = new List<double>();
			BitwiseDict = new Dictionary<double, bool>()
			{
				[1] = false,
				[2] = false,
				[4] = false,
				[8] = false,
				[16] = false,
				[32] = false,
				[64] = false,
				[128] = false,
				[256] = false,
				[512] = false,
				[1024] = false,
				[2048] = false,
				[4096] = false,
				[8192] = false,
				[16384] = false,
				[32768] = false,
				[65536] = false,
				[131072] = false,
				[262144] = false,
				[524288] = false,
				[1048576] = false,
				[2097152] = false,
				[4194304] = false,
				[8388608] = false,
				[16777216] = false,
				[33554432] = false,
				[67108864] = false,
				[134217728] = false,
				[268435456] = false,
				[536870912] = false,
				[1073741824] = false,
				[2147483648] = false,
			};
        }

        // Constructor that takes one argument.
        public LdapValueContext(List<LdapValueParsed> contentParsedList)
		{
			Format = LdapTokenFormat.Undefined;
			Content = string.Concat(contentParsedList.Select(parsedChar => parsedChar.Content));
			ContentDecoded = string.Concat(contentParsedList.Select(parsedChar => parsedChar.ContentDecoded));
			ContentParsedList = contentParsedList;
			BitwiseAddend = new List<double>();
			BitwiseDict = new Dictionary<double, bool>()
			{
				[1] = false,
				[2] = false,
				[4] = false,
				[8] = false,
				[16] = false,
				[32] = false,
				[64] = false,
				[128] = false,
				[256] = false,
				[512] = false,
				[1024] = false,
				[2048] = false,
				[4096] = false,
				[8192] = false,
				[16384] = false,
				[32768] = false,
				[65536] = false,
				[131072] = false,
				[262144] = false,
				[524288] = false,
				[1048576] = false,
				[2097152] = false,
				[4194304] = false,
				[8388608] = false,
				[16777216] = false,
				[33554432] = false,
				[67108864] = false,
				[134217728] = false,
				[268435456] = false,
				[536870912] = false,
				[1073741824] = false,
				[2147483648] = false,
			};
        }

        // Auto-implemented readonly properties.
		public LdapTokenFormat Format { get; set; }
        public string Content { get; set; }
		public string ContentDecoded { get; set; }
		public List<LdapValueParsed> ContentParsedList { get; set; }
		public List<double> BitwiseAddend { get; set; }
		public Dictionary<double, bool> BitwiseDict { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Content: {Content}, ContentDecoded: {ContentDecoded}, ContentParsedList: {ContentParsedList}, BitwiseAddend: {BitwiseAddend}";
        }
    }

    /// <summary>
    /// This class defines objects for individually-parsed characters from Value token, notably
	/// including character Format, Class, Case and decoded Content properties.
	/// </summary>
    public class LdapValueParsed
    {
        // Constructor that takes no arguments.
        public LdapValueParsed()
        {
			Content = null;
			ContentDecoded = null;
			IsDecoded = false;
			Format = LdapValueParsedFormat.Undefined;
			Class = CharClass.Undefined;
			Case = CharCase.Undefined;
			IsPrintable = false;
        }

        // Constructor that takes two arguments.
        public LdapValueParsed(string content, string contentDecoded)
		{
			Content = content;
			ContentDecoded = contentDecoded;
			IsDecoded = false;
			Format = content.StartsWith('\\') ? LdapValueParsedFormat.EscapedUnknown : LdapValueParsedFormat.Undefined;
			Class = CharClass.Undefined;
			Case = CharCase.Undefined;
			IsPrintable = false;
        }

		// Constructor that takes six arguments.
        public LdapValueParsed(string content, string contentDecoded, LdapValueParsedFormat format, CharClass charClass, CharCase charCase, bool isPrintable)
		{
			Content = content;
			ContentDecoded = contentDecoded;
			IsDecoded = (format == LdapValueParsedFormat.Hex) ? true : false;
			Format = format;
			Class = charClass;
			Case = charCase;
			IsPrintable = isPrintable;
        }

        // Auto-implemented readonly properties.
        public string Content { get; set; }
		public string ContentDecoded { get; set; }
        public bool IsDecoded { get; set; }
        public LdapValueParsedFormat Format { get; set; }
        public CharClass Class { get; set; }
        public CharCase Case { get; set; }
        public bool IsPrintable { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Content: {Content}, ContentDecoded: {ContentDecoded}, IsDecoded: {IsDecoded}, Format: {Format}, Class: {Class}, Case: {Case}, IsPrintable: {IsPrintable}";
        }
    }

    /// <summary>
    /// This class defines objects containing ASCII character metadata that define charContextDict
	/// Dictionary used for efficient lookups in LDAP Value parsing and feature extraction purposes.
	/// </summary>
    public class CharContext
    {
        // Constructor that takes no arguments.
        public CharContext()
        {
			Content = null;
			Class = CharClass.Undefined;
			Case = CharCase.Undefined;
			IsPrintable = false;
			IsHex = false;
        }

        // Constructor that takes five arguments.
        public CharContext(char content, CharClass charClass, CharCase charCase, bool isPrintable, bool isHex)
		{
			Content = content;
			Class = charClass;
			Case = charCase;
			IsPrintable = isPrintable;
			IsHex = isHex;
        }

        // Auto-implemented readonly properties.
        public Nullable<char> Content { get; set; }
		public CharClass Class { get; set; }
        public CharCase Case { get; set; }
        public bool IsPrintable { get; set; }
        public bool IsHex { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Content: {Content}, Class: {Class}, Case: {Case}, IsPrintable: {IsPrintable}, IsHex: {IsHex}";
        }
    }

    /// <summary>
    /// This class defines object storing all enriched tokens in single LDAP Filter (which is part
	/// of overall LDAP SearchFilter).
	/// </summary>
    public class LdapFilter
    {
        // Constructor that takes no arguments.
        public LdapFilter()
        {
            Content = null;
            ContentDecoded = null;
            Start = -1;
            Length = -1;
            Depth = -1;
            BooleanOperator = null;
            Attribute = null;
            AttributeDecoded = null;
            ExtensibleMatchFilter = null;
            ExtensibleMatchFilterDecoded = null;
            ComparisonOperator = null;
            Value = null;
            ValueDecoded = null;
            TokenDict = new Dictionary<LdapTokenType, LdapTokenEnriched>();
            TokenList = new List<LdapTokenEnriched>();
			Context = new LdapContext();
        }

        // Constructor that takes one argument.
        public LdapFilter(List<LdapTokenEnriched> filterTokenList)
        {
			// Call helper method to translate list of enriched tokens into single LdapFilter object.
			LdapFilter ldapFilter = ConvertToLdapFilter(filterTokenList);

            // Set all properties from resultant LdapFilter object above in below properties for constructor.
            Content = ldapFilter.Content;
            ContentDecoded = ldapFilter.ContentDecoded;
            Start = ldapFilter.Start;
            Length = ldapFilter.Length;
            Depth = ldapFilter.Depth;
            BooleanOperator = ldapFilter.BooleanOperator;
            Attribute = ldapFilter.Attribute;
            AttributeDecoded = ldapFilter.AttributeDecoded;
            ExtensibleMatchFilter = ldapFilter.ExtensibleMatchFilter;
            ExtensibleMatchFilterDecoded = ldapFilter.ExtensibleMatchFilterDecoded;
            ComparisonOperator = ldapFilter.ComparisonOperator;
            Value = ldapFilter.Value;
            ValueDecoded = ldapFilter.ValueDecoded;
            TokenDict = ldapFilter.TokenDict;
            TokenList = ldapFilter.TokenList;
			Context = ldapFilter.Context;
        }

        // Auto-implemented readonly properties.
        public string Content { get; set; }
        public string ContentDecoded { get; set; }
        public int Start { get; set; }
        public int Length { get; set; }
        public int Depth { get; set; }
        public string BooleanOperator { get; set; }
        public string Attribute { get; set; }
        public string AttributeDecoded { get; set; }
        public string ExtensibleMatchFilter { get; set; }
        public string ExtensibleMatchFilterDecoded { get; set; }
        public string ComparisonOperator { get; set; }
        public string Value { get; set; }
        public string ValueDecoded { get; set; }
        public Dictionary<LdapTokenType, LdapTokenEnriched> TokenDict { get; set; }
        public List<LdapTokenEnriched> TokenList { get; set; }
        public LdapContext Context { get; set; }

		/// <summary>
		/// This helper method translates list of enriched tokens into single LdapFilter object.
		/// </summary>
        private static LdapFilter ConvertToLdapFilter(List<LdapTokenEnriched> filterTokenList)
        {
            // Iterate over input filterTokenList, capturing below subset of Filter tokens for more
			// targeted and efficient detection authoring.
			LdapTokenEnriched filterTokenGroupStart = null;
            LdapTokenEnriched filterTokenBooleanOperator = null;
            LdapTokenEnriched filterTokenAttribute = null;
            LdapTokenEnriched filterTokenExtensibleMatchFilter = null;
            LdapTokenEnriched filterTokenComparisonOperator = null;
            LdapTokenEnriched filterTokenValue = null;

            // Additionally, create StringBuilder objects to build single string containing concatenated
			// Content and ContentDecoded property values in below filterTokenList traversal.
            StringBuilder sbFilterTokenListContent = new StringBuilder();
            StringBuilder sbFilterTokenListContentDecoded = new StringBuilder();

            foreach (LdapTokenEnriched filterToken in filterTokenList)
            {
                // Append current look-ahead token's Content and ContentDecoded properties to StringBuilder.
                sbFilterTokenListContent.Append(filterToken.Content);
                sbFilterTokenListContentDecoded.Append(filterToken.ContentDecoded);

                // Capture subset of Filter tokens that exclude Whitespace for more targeted and
				// efficient detection authoring.
                switch (filterToken.Type)
                {
					case LdapTokenType.GroupStart:
						filterTokenGroupStart = filterToken;
						break;
                    case LdapTokenType.BooleanOperator:
                        filterTokenBooleanOperator = filterToken;
                        break;
                    case LdapTokenType.Attribute:
                        filterTokenAttribute = filterToken;
                        break;
                    case LdapTokenType.ExtensibleMatchFilter:
                        filterTokenExtensibleMatchFilter = filterToken;
                        break;
                    case LdapTokenType.ComparisonOperator:
                        filterTokenComparisonOperator = filterToken;
                        break;
                    case LdapTokenType.Value:
                        filterTokenValue = filterToken;
                        break;
                }
            }

            // Extract first token from current Filter.
			LdapTokenEnriched filterTokenListFirst = filterTokenList[0];

            // Create new LdapFilter object.
            LdapFilter ldapFilter = new LdapFilter();

			// Transpose simple values from above subset of Filter tokens onto newly created
			// LdapFilter object.
            ldapFilter.Content = sbFilterTokenListContent.ToString();
            ldapFilter.ContentDecoded = sbFilterTokenListContentDecoded.ToString();
            ldapFilter.Start = filterTokenListFirst.Start;
            ldapFilter.Length = sbFilterTokenListContent.ToString().Length;
            ldapFilter.Depth = filterTokenListFirst.Depth;
            ldapFilter.BooleanOperator = filterTokenBooleanOperator != null ? filterTokenBooleanOperator.Content : null;
            ldapFilter.Attribute = filterTokenAttribute.Content;
            ldapFilter.AttributeDecoded = filterTokenAttribute.ContentDecoded;
            ldapFilter.ExtensibleMatchFilter = filterTokenExtensibleMatchFilter != null ? filterTokenExtensibleMatchFilter.Content : null;
            ldapFilter.ExtensibleMatchFilterDecoded = filterTokenExtensibleMatchFilter != null ? filterTokenExtensibleMatchFilter.ContentDecoded : null;
            ldapFilter.ComparisonOperator = filterTokenComparisonOperator.Content;
            ldapFilter.Value = filterTokenValue.Content;
            ldapFilter.ValueDecoded = filterTokenValue.ContentDecoded;

            // Create Dictionary for significant LDAP Filter tokens for faster lookup of complete
			// LdapTokenEnriched objects.
			Dictionary<LdapTokenType, LdapTokenEnriched> filterTokenDict = new Dictionary<LdapTokenType, LdapTokenEnriched>()
            {
                [LdapTokenType.BooleanOperator] = filterTokenBooleanOperator,
                [LdapTokenType.Attribute] = filterTokenAttribute,
                [LdapTokenType.ExtensibleMatchFilter] = filterTokenExtensibleMatchFilter,
                [LdapTokenType.ComparisonOperator] = filterTokenComparisonOperator,
                [LdapTokenType.Value] = filterTokenValue
            };

			// Add final token objects to newly created LdapFilter object.
            ldapFilter.TokenDict = filterTokenDict;
            ldapFilter.TokenList = filterTokenList;

			// Finally, add all Context objects stored in leading GroupStart token since this is where
			// filter-context information is stored in initial tokenization of LDAP SearchFilter.
			ldapFilter.Context = filterTokenGroupStart.Context;

			// Return newly created LdapFilter object with all input token values transposed.
            return ldapFilter;
        }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Depth: {Depth}, Length: {Length}, Content: {Content}";
        }
    }

    /// <summary>
    /// This class defines object storing all enriched tokens and LDAP Filter objects comprising an
	/// LDAP branch (which is a nested parse tree/syntax tree structure containing entire LDAP SearchFilter).
	/// </summary>
    public class LdapBranch
    {
        // Constructor that takes no arguments.
        public LdapBranch()
        {
			Content = null;
			ContentDecoded = null;
            Type = LdapBranchType.FilterList;
            Branch = new List<object>();
			Start = -1;
			Length = -1;
            Depth = -1;
            DepthMax = -1;
			BooleanOperatorCountMax = -1;
			BooleanOperatorLogicalCountMax = -1;
            BooleanOperator = null;
			Context = new LdapContext();
            Index = -1;
        }

        // Constructor that takes three arguments.
		public LdapBranch(LdapBranchType type, int index, int depth)
        {
			Content = null;
			ContentDecoded = null;
            Type = type;
            Branch = new List<object>();
			Start = -1;
			Length = -1;
            Depth = depth;
			DepthMax = depth;
			BooleanOperatorCountMax = -1;
			BooleanOperatorLogicalCountMax = -1;
            BooleanOperator = null;
			Context = new LdapContext();
            Index = index;
        }

		// Constructor that takes LdapFilter and initializes it in new LdapBranch of Filter branch type.
        public LdapBranch(LdapFilter ldapFilter)
        {
			Content = ldapFilter.Content;
			ContentDecoded = ldapFilter.ContentDecoded;
            Type = LdapBranchType.Filter;
            Branch = new List<object>()
			{
				ldapFilter
			};
			Start = ldapFilter.Start;
			Length = ldapFilter.Length;
			Depth = ldapFilter.Depth;
			DepthMax = ldapFilter.Depth;
			BooleanOperatorCountMax = ldapFilter.Context.BooleanOperator.HistoricalBooleanOperatorCount;
			// If wildcard character (escaped or unescaped) is present in a filter then the logical
			// historical BooleanOperator count should increase by one (since the limit of permitted
			// BooleanOperators decreases by one).
			BooleanOperatorLogicalCountMax = ldapFilter.Content.Contains('*') ? ldapFilter.Context.BooleanOperator.HistoricalBooleanOperatorCount + 1 : ldapFilter.Context.BooleanOperator.HistoricalBooleanOperatorCount;
            BooleanOperator = ldapFilter.BooleanOperator;
			Context = ldapFilter.Context;
            Index = -1;
        }

        // Auto-implemented readonly properties.
        public int Start { get; set; }
        public int Length { get; set; }
        public string Content { get; set; }
        public string ContentDecoded { get; set; }
        public int Depth { get; set; }
        public int DepthMax { get; set; }
		public int BooleanOperatorCountMax { get; set; }
		public int BooleanOperatorLogicalCountMax { get; set; }
        public LdapBranchType Type { get; set; }
        public List<object> Branch { get; set; }
        public string BooleanOperator { get; set; }
		public LdapContext Context { get; set;}
		// Index property is only used for advancing token index based on recursive results returned.
        public int Index { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
            return $"Start: {Start}, Length: {Length}, Depth: {Depth}, DepthMax: {DepthMax}, BooleanOperatorCountMax: {BooleanOperatorCountMax}, BooleanOperatorLogicalCountMax: {BooleanOperatorLogicalCountMax}, Index: {Index}, Type: {Type}, BooleanOperator: {BooleanOperator}, FilterListBooleanOperatorDistance: {Context.BooleanOperator.FilterListBooleanOperatorDistance}, FilterListBooleanOperator(count={Context.BooleanOperator.FilterListBooleanOperatorTokenListCount}): {Context.BooleanOperator.FilterListBooleanOperator}, FilterBooleanOperator(count={Context.BooleanOperator.FilterBooleanOperatorTokenListCount}): {Context.BooleanOperator.FilterBooleanOperator}";
        }
    }

    /// <summary>
    /// This class defines per-rule Detection information generated for suspicious LDAP SearchFilter.
	/// </summary>
    public class Detection
    {
        // Constructor that takes seven arguments for LdapFilter input.
        public Detection(LdapFilter ldapFilter, string author, DateTime date, DetectionID id, string name, string example, double score)
        {
			// Detection input type.
			Type = LdapBranchType.Filter;
			//
			// Detection rule metadata.
			Author = author;
			Date = date;
			ID = id;
			Name = name;
			Example = example;
			Score = score;
			//
			// Detection hit context.
			Depth = ldapFilter.Depth;
			Start = ldapFilter.Start;
			Content = ldapFilter.Content;
			ContentDecoded = ldapFilter.ContentDecoded;
        }

        // Constructor that takes seven arguments for LdapBranch input.
        public Detection(LdapBranch ldapBranch, string author, DateTime date, DetectionID id, string name, string example, double score)
        {
			// Detection input type.
			Type = ldapBranch.Type;
			//
			// Detection rule metadata.
			Author = author;
			Date = date;
			ID = id;
			Name = name;
			Example = example;
			Score = score;
			//
			// Detection hit context.
			Depth = ldapBranch.Depth;
			Start = ldapBranch.Start;
			Content = ldapBranch.Content;
			ContentDecoded = ldapBranch.ContentDecoded;
        }

        // Auto-implemented readonly properties.
		//
		// Detection input type.
        public LdapBranchType Type { get; set; }
		//
		// Detection rule metadata.
        public string Author { get; set; }
        public DateTime Date { get; set; }
        public DetectionID ID { get; set; }
        public string Name { get; set; }
        public string Example { get; set; }
        public double Score { get; set; }
		//
		// Detection hit context.
        public int Depth { get; set; }
        public int Start { get; set; }
        public string Content { get; set; }
        public string ContentDecoded { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
			return $"Score={Score}, ID={ID}, Name={Name}, Depth={Depth}, Start={Start}, Content={Content}, ContentDecoded={ContentDecoded}";
        }
    }

    /// <summary>
    /// This class defines Detection information summarized for all matching Detection rule(s) generated for suspicious LDAP SearchFilter.
	/// </summary>
    public class DetectionSummary
    {
        // Constructor that takes zero-to-one arguments.
        public DetectionSummary(string searchFilter = "")
        {
			// Detection rule metadata.
			TotalScore = 0.0;
			DetectionCount = 0;
			Detections = new List<Detection>();
			UniqueDetectionIDCount = 0;
			UniqueDetectionIDs = new List<DetectionID>();
			UniqueDetectionNameCount = 0;
			UniqueDetectionNames = new List<string>();
			//
			// Detection hit context.
			SearchFilterLength = searchFilter.Length;
			SearchFilter = searchFilter;
        }

        // Constructor that takes four-to-five arguments.
        public DetectionSummary(double totalScore, List<Detection> detections, List<DetectionID> uniqueDetectionIDs, List<string> uniqueDetectionNames, string searchFilter = "")
        {
			// Detection rule metadata.
			TotalScore = totalScore;
			DetectionCount = detections.Count;
			Detections = detections;
			UniqueDetectionIDCount = uniqueDetectionIDs.Count;
			UniqueDetectionIDs = uniqueDetectionIDs;
			UniqueDetectionNameCount = uniqueDetectionNames.Count;
			UniqueDetectionNames = uniqueDetectionNames;
			//
			// Detection hit context.
			SearchFilterLength = searchFilter.Length;
			SearchFilter = searchFilter;
        }

        // Auto-implemented readonly properties.
		//
		// Detection rule metadata.
        public double TotalScore { get; set; }
        public int DetectionCount { get; set; }
        public List<Detection> Detections { get; set; }
        public int UniqueDetectionIDCount { get; set; }
        public List<DetectionID> UniqueDetectionIDs { get; set; }
        public int UniqueDetectionNameCount { get; set; }
        public List<string> UniqueDetectionNames { get; set; }
		//
		// Detection hit context.
		public int SearchFilterLength { get; set; }
        public string SearchFilter { get; set; }

        // Method that overrides the base class (System.Object) implementation.
        public override string ToString()
        {
			return $"TotalScore={TotalScore}, DetectionCount={DetectionCount}, UniqueDetectionIDCount={UniqueDetectionIDCount}, UniqueDetectionNameCount={UniqueDetectionNameCount}, SearchFilterLength={SearchFilterLength}, SearchFilter={SearchFilter}";
        }
    }

    /// <summary>
    /// This class defines LDAP parser for tokenization (LdapToken), enriched tokenization
	/// (LdapTokenEnriched), filter-level grouping of enriched tokens (LdapFilter) and
	/// parse tree/syntax tree representation (LdapBranch) of entire LDAP SearchFilter.
	/// </summary>
    public class LdapParser
    {
        #region Static fields

        // Define Dictionary containing eligible first character(s) for each LDAP token type.
        // This will be used for more performantly identifying LDAP token types by only
        // evaluating the first character before potential Regex checks (defined below).
        public static readonly IReadOnlyDictionary<LdapTokenType, char[]> ldapTokenTypeLeadingCharDict = new Dictionary<LdapTokenType, char[]>()
        {
            [LdapTokenType.GroupStart] = new char[] { '(' },
            [LdapTokenType.GroupEnd] = new char[] { ')' },
            [LdapTokenType.BooleanOperator] = new char[] { '&', '|', '!' },
            [LdapTokenType.ExtensibleMatchFilter] = new char[] { ':' },
            // Potential ComparisonOperator prefixes (e.g. '<', '>', '~') are handled
			// separately later in method since more performant to focus on '=' only.
            [LdapTokenType.ComparisonOperator] = new char[] { '=' },
			[LdapTokenType.Whitespace] = new char[] { ' ' },
        };

        // Define Dictionary containing eligible leading Regex for each LDAP token format.
		// This will be evaluated against entire extracted applicable LDAP token.
        // Below Regex values are configured to be compiled for performance.
		public static readonly IReadOnlyDictionary<LdapTokenFormat, Regex> ldapTokenFormatRegexDict = new Dictionary<LdapTokenFormat, Regex>()
		{
			[LdapTokenFormat.OID] = new Regex(@"^(?<oid_prefix>OID.)?(?<oid_octets>\d+(\.\d+)+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase)
		};

        // Define Regex for server-side LDAP logging shorthand format for ExtensibleMatchFilters.
		// This shorthand syntax technically produces an invalid LDAP SearchFilter, so will be normalized to valid ExtensibleMatchFilter+ComparisonOperator tokens.
		// E.g. (options&1) => (options:1.2.840.113556.1.4.803:=1)
        // E.g. (userAccountControl|67117056) => (userAccountControl:1.2.840.113556.1.4.804:= 67117056)
        // E.g. (distinguishedName<==>CN=dbo,CN=Users,DC=contoso,DC=local) => (distinguishedName:1.2.840.113556.1.4.1941:=CN=dbo,CN=Users,DC=contoso,DC=local)
		// Below Regex value is configured to be compiled for performance.
		public static Regex ldapComparisonOperatorAndValueServerLogShorthandFormat = new Regex(@"(?<extensible_match_filter>(&|\||<==>))(?<attribute_value>(.+)+)$", RegexOptions.Compiled);

        // Define RDN control characters required for RDN obfuscation.
        //   - Backslash escape character: E.g. hex encoded comma ('\2C' or '\2c') or equals ('\3D' or '\3d') characters.
        //   - Double quote encapsulation: "
        public static char[] rdnObfuscationPrereqControlCharArr = new char[] { '\\', '"' };

        // Define Regex for double quote encapsulated string.
        // Escaped double quotes will be sanitized by SanitizeRdn method below before executing this Regex.
		// Below Regex value is configured to be compiled for performance.
        public static Regex rdnDoubleQuoteEncapsulationCaptureGroupPattern = new Regex("(\"[^\"]*\")", RegexOptions.Compiled);

        // Define substring to prepend to escaped or hex-encoded control characters for consistent
        // sanitization and later parsing.
        public static string ldapRdnSanitizedControlCharPrefix = "__";
        public static string ldapRdnSanitizedControlCharHexPrefix = "\0\0";

		#endregion

		/// <summary>
		/// This method sanitizes potential hex-encoded RDN (Relative Distinguished Name) control characters in input LDAP Attribute Value for more efficient RDN validation in IsRdn method and RDN parsing in TokenizeRdn method.
		/// </summary>
        public static string SanitizeRdn(string ldapAttributeValue)
        {
            // Return input ldapAttributeValue as-is if null or empty.
            if (ldapAttributeValue.Length == 0)
            {
                return ldapAttributeValue;
            }

            // Return LDAP Attribute Value string as-is if no obfuscation prerequisite control characters are found.
            if (ldapAttributeValue.IndexOfAny(rdnObfuscationPrereqControlCharArr) == -1)
            {
                return ldapAttributeValue;
            }

            // If backslash escape character exists in input LDAP Attribute Value, perform
            // sanitization of all relevant escaped and/or hex-encoded values if they exist.
            // This enables more efficient parsing later.
            if (ldapAttributeValue.Contains(@"\"))
            {
                // Sanitize all escaped backslash, equal, comma or double quote characters (if they exist).
                ldapAttributeValue = ldapAttributeValue.Replace(@"\\", ldapRdnSanitizedControlCharPrefix);
                ldapAttributeValue = ldapAttributeValue.Replace(@"\=", ldapRdnSanitizedControlCharPrefix);
                ldapAttributeValue = ldapAttributeValue.Replace(@"\,", ldapRdnSanitizedControlCharPrefix);
                ldapAttributeValue = ldapAttributeValue.Replace(@"\""", ldapRdnSanitizedControlCharPrefix);

                // Sanitize all hex-encoded equal ('\3D' or '\3d') characters (if they exist).
                if (ldapAttributeValue.Contains(@"\3"))
                {
                    ldapAttributeValue = ldapAttributeValue.Replace(@"\3D", $"{ldapRdnSanitizedControlCharHexPrefix}=");
                    ldapAttributeValue = ldapAttributeValue.Replace(@"\3d", $"{ldapRdnSanitizedControlCharHexPrefix}=");
                }

                // Sanitize all hex-encoded comma ('\2C' or '\2c') and whitespace ('\20') characters (if they exist).
                if (ldapAttributeValue.Contains(@"\2"))
                {
                    ldapAttributeValue = ldapAttributeValue.Replace(@"\2C", $"{ldapRdnSanitizedControlCharHexPrefix},");
                    ldapAttributeValue = ldapAttributeValue.Replace(@"\2c", $"{ldapRdnSanitizedControlCharHexPrefix},");

                    // Use whitespace as the prefix for hex-encoded whitespace so encapsulated whitespace parsing logic can remain simplified.
                    ldapAttributeValue = ldapAttributeValue.Replace(@"\20", "   ");
                }
            }

            // If double quote exists in input LDAP Attribute Value, sanitize all double quote encapsulated substrings.
            if (ldapAttributeValue.Contains(@""""))
            {
                // Sanitize all double quote encapsulated substrings in input LDAP Attribute Value.
                foreach (Match match in rdnDoubleQuoteEncapsulationCaptureGroupPattern.Matches(ldapAttributeValue))
                {
                    // Extract double quote encapsulated substring from Regex capture group
                    // and generate sanitized substring of the same length.
                    string doubleQuoteEncapsulatedSubstring = match.Groups[1].ToString();
                    string sanitizedSubstring = string.Concat(Enumerable.Repeat("_", doubleQuoteEncapsulatedSubstring.Length));
                    int doubleQuoteEncapsulatedSubstringIndex = ldapAttributeValue.IndexOf(doubleQuoteEncapsulatedSubstring);

                    // Replace first instance of current extracted double quote encapsulated substring with equal-length sanitized substring.
                    ldapAttributeValue = ldapAttributeValue.Substring(0, doubleQuoteEncapsulatedSubstringIndex) + sanitizedSubstring + ldapAttributeValue.Substring(doubleQuoteEncapsulatedSubstringIndex + sanitizedSubstring.Length);
                }
            }

            //  Return sanitized LDAP Attribute Value string.
            return ldapAttributeValue;
        }

		/// <summary>
		/// This method validates if input LDAP Attribute Value is an RDN (Relative Distinguished Name).
		/// </summary>
        public static bool IsRdn(string ldapAttributeValue)
        {
            // Return false if input ldapAttributeValue string is null or empty.
            if (ldapAttributeValue.Length == 0)
            {
                return false;
            }

            // Sanitize RDN to facilitate more efficient control character evaluation.
            // This removes the need for current method to handle escape and/or hex-encoded
            // control character identification (and double quote encapsulation scenario) for
            // simplified and more efficient RDN validation.
            string ldapAttributeValueSanitized = SanitizeRdn(ldapAttributeValue);

			// Remove potential single leading equal character from RDN in case of rare '==' comparison operator.
			ldapAttributeValueSanitized = LdapParser.TrimStartOne(ldapAttributeValueSanitized, '=');

            // Valid RDN must at least contain an equal character, so return false if condition not met.
            if (!ldapAttributeValueSanitized.Contains("="))
            {
                return false;
            }

            // Valid RDN or array of RDN's (e.g. DN composed of multiple RDNs joined by comma
            // delimiter) should always contain one more equal characters (required per RDN)
            // than comma characters (RDN delimiter).

            // Calculate number of equal character, comma characters and count difference.
            int unescapedEqualCharCount = ldapAttributeValueSanitized.Length - ldapAttributeValueSanitized.Replace("=", "").Length;
            int unescapedCommaCharCount = ldapAttributeValueSanitized.Length - ldapAttributeValueSanitized.Replace(",", "").Length;
            int unescapedEqualMinusCommaCharCount = unescapedEqualCharCount - unescapedCommaCharCount;

            // If equal-to-comma count difference is invalid then return false.
            if (unescapedEqualMinusCommaCharCount != 1)
            {
                return false;
            }

			// If equal-to-comma count difference is valid and at least one comma exists then perform additional per-RDN checks.
			if (unescapedCommaCharCount > 0)
			{
				// Create array of RDNs by splitting sanitized DN value on comma character (RDN delimiter).
				string[] rdnList = ldapAttributeValueSanitized.Split(",");

				// Calculate count of RDNs correctly containing a single equal character with at least
				// one character preceding and succeeding it.
				int validRdnCount = rdnList.Where(rdn => ((rdn.Length - rdn.Replace("=", "").Length) == 1) && (rdn.IndexOf("=") > 0) && (rdn.IndexOf("=") < rdn.Length - 1)).Count();

				// If any RDN fails to meet above validation then return false.
				if (validRdnCount < rdnList.Length)
				{
					return false;
				}
			}

            // Return true since current input Attribute Value is valid RDN.
            return true;
        }

		/// <summary>
		/// This method normalizes input LDAP OID (Object ID) string by removing potential "OID." prefix and any unnecessary leading 0's per OID octet.
		/// </summary>
        public static string NormalizeOid(string ldapOid)
        {
            // Return input LDAP OID string as-is if null or empty.
            if (ldapOid.Length == 0)
            {
                return ldapOid;
            }

			// Perform Regex evaluation against input LDAP OID string to extract OID octets via Regex capture group.
			Match match = ldapTokenFormatRegexDict[LdapTokenFormat.OID].Match(ldapOid);
			if (match.Success)
			{
				// Update input OID string to Regex match capture group for OID octets (removing potential "OID." prefix).
				ldapOid = match.Groups["oid_octets"].ToString();

				// Split OID into string array of octets and remove potential leading zero characters (unless entire octet
				// is legitimately a single zero character) before rejoining as single string.
				string[] ldapOidOctets = ldapOid.Split('.');
				for (int i = 0; i < ldapOidOctets.Length; i++)
				{
					// Trim any and all leading zero characters from current OID octet.
					ldapOidOctets[i] = ldapOidOctets[i].TrimStart('0');

					// If entire OID octet is legitimately a single zero character then replace the null octet with a single zero character.
					if (ldapOidOctets[i].Length == 0)
					{
						ldapOidOctets[i] = "0";
					}
				}
				ldapOid = string.Join(".", ldapOidOctets);
			}

            // Return normalized LDAP OID string.
            return ldapOid;
        }

		/// <summary>
		/// This method validates if input LDAP token's Content value is in OID format (accounting for many obfuscated variations of OID syntax).
		/// </summary>
        public static bool IsOid(string ldapAttributeOrExtensibleMatchFilter)
        {
            // Return false if input ldapAttributeOrExtensibleMatchFilter string is null or empty.
            if (ldapAttributeOrExtensibleMatchFilter.Length == 0)
            {
                return false;
            }

            // Return false if input Attribute or ExtensibleMatchFilter does not contain a period character since it is required for OID format.
			if (ldapAttributeOrExtensibleMatchFilter.IndexOf('.') == -1)
			{
                return false;
            }

			// Perform Regex evaluation against input Attribute or ExtensibleMatchFilter to determine if OID format.
			Match match = ldapTokenFormatRegexDict[LdapTokenFormat.OID].Match(ldapAttributeOrExtensibleMatchFilter);
			if (match.Success)
			{
				return true;
			}

            // Return false since current input Attribute or ExtensibleMatchFilter is not OID format.
            return false;
        }

		/// <summary>
		/// This Dictionary defines OID->Name mappings for the four (4) ExtensibleMatchFilter rules that Microsoft Active Directory supports.
		/// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5
		/// Source: https://github.com/MicrosoftDocs/win32/blob/0e611cdff84ff9f897c59e4e1d2b2d134bc4e133/desktop-src/ADSI/search-filter-syntax.md
		/// </summary>
		public static readonly IReadOnlyDictionary<string, string> ldapExtensibleMatchFilterOidDict = new Dictionary<string, string>()
		{
			{ "1.2.840.113556.1.4.803","LDAP_MATCHING_RULE_BIT_AND" },
			{ "1.2.840.113556.1.4.804","LDAP_MATCHING_RULE_BIT_OR" },
			{ "1.2.840.113556.1.4.1941","LDAP_MATCHING_RULE_IN_CHAIN" },
			{ "1.2.840.113556.1.4.2253","LDAP_MATCHING_RULE_DN_WITH_DATA" },
		};

		/// <summary>
		/// This Dictionary defines Name->Context object mappings for the four (4) ExtensibleMatchFilter rules that Microsoft Active Directory supports.
		/// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5
		/// Source: https://github.com/MicrosoftDocs/win32/blob/0e611cdff84ff9f897c59e4e1d2b2d134bc4e133/desktop-src/ADSI/search-filter-syntax.md
		/// </summary>
		public static readonly IReadOnlyDictionary<string, LdapExtensibleMatchFilterContext> ldapExtensibleMatchFilterContextDict = new Dictionary<string, LdapExtensibleMatchFilterContext>(StringComparer.OrdinalIgnoreCase)
		{
			{ "LDAP_MATCHING_RULE_BIT_AND", new LdapExtensibleMatchFilterContext("LDAP_MATCHING_RULE_BIT_AND","1.2.840.113556.1.4.803","A match is found only if all bits from the attribute match the value. This rule is equivalent to a bitwise AND operator.") },
			{ "LDAP_MATCHING_RULE_BIT_OR", new LdapExtensibleMatchFilterContext("LDAP_MATCHING_RULE_BIT_OR","1.2.840.113556.1.4.804","A match is found if any bits from the attribute match the value. This rule is equivalent to a bitwise OR operator.") },
			{ "LDAP_MATCHING_RULE_IN_CHAIN", new LdapExtensibleMatchFilterContext("LDAP_MATCHING_RULE_IN_CHAIN","1.2.840.113556.1.4.1941","This rule is limited to filters that apply to the DN. This is a special \"extended\" match operator that walks the chain of ancestry in objects all the way to the root until it finds a match.") },
			{ "LDAP_MATCHING_RULE_DN_WITH_DATA", new LdapExtensibleMatchFilterContext("LDAP_MATCHING_RULE_DN_WITH_DATA","1.2.840.113556.1.4.2253","This rule provides a way to match on portions of values of DN Syntax and Object(DN-Binary).") },
		};

		/// <summary>
		/// This method returns full Context object for input ExtensibleMatchFilter value (regardless of format or potential obfuscation).
		/// </summary>
		public static LdapExtensibleMatchFilterContext GetLdapExtensibleMatchFilter(string ldapExtensibleMatchFilter,bool allowNonOidSyntax = false)
		{
			// Return empty LdapExtensibleMatchFilterContext object if input ldapExtensibleMatchFilter string is null or empty.
			if (ldapExtensibleMatchFilter.Length == 0)
			{
				return new LdapExtensibleMatchFilterContext();
			}

			// If input ExtensibleMatchFilter is in OID format then return ExtensibleMatchFilter name if defined in ExtensibleMatchFilter Dictionary.
			if (LdapParser.IsOid(ldapExtensibleMatchFilter))
			{
				// Perform simple extraction of input ExtensibleMatchFilter and not full OID normalization since ExtensibleMatchFilter does not support OID obfuscation like Attribute.

				// Extract ExtensibleMatchFilter by removing single leading and trailing colon characters if present.
				string ldapExtensibleMatchFilterOidExtracted = LdapParser.TrimOne(ldapExtensibleMatchFilter, ':');

				// If input ExtensibleMatchFilter OID is not defined in ExtensibleMatchFilter OID Dictionary then return empty LdapExtensibleMatchFilterContext object.
				if (!ldapExtensibleMatchFilterOidDict.ContainsKey(ldapExtensibleMatchFilterOidExtracted))
				{
					return new LdapExtensibleMatchFilterContext();
				}

				// Update extracted input ExtensibleMatchFilter with name from OID Dictionary.
				ldapExtensibleMatchFilter = ldapExtensibleMatchFilterOidDict[ldapExtensibleMatchFilterOidExtracted];
			}
			else if (allowNonOidSyntax == false)
			{
				// If input ExtensibleMatchFilter is not in OID format and default value for allowNonOidSyntax boolean input parameter is not overridden then
				// return empty LdapExtensibleMatchFilterContext object since ExtensibleMatchFilter does not support non-OID syntax like Attribute.
				return new LdapExtensibleMatchFilterContext();
			}

			// If input ExtensibleMatchFilter name is not defined in ExtensibleMatchFilter context Dictionary then return empty LdapExtensibleMatchFilterContext object.
			if (!ldapExtensibleMatchFilterContextDict.ContainsKey(ldapExtensibleMatchFilter))
			{
				return new LdapExtensibleMatchFilterContext();
			}

			// Return ExtensibleMatchFilter Context object returned from Dictionary.
			return ldapExtensibleMatchFilterContextDict[ldapExtensibleMatchFilter];
		}

		/// <summary>
		/// This Dictionary defines OID->Name mappings for all defined LDAP Attributes that Microsoft Active Directory supports.
		/// Source: https://github.com/MicrosoftDocs/win32/tree/docs/desktop-src/ADSchema
		/// </summary>
		public static readonly IReadOnlyDictionary<string, string> ldapAttributeOidDict = new Dictionary<string, string>()
		{
			{ "0.9.2342.19200300.100.1.1","uid" },
			{ "0.9.2342.19200300.100.1.10","manager" },
			{ "0.9.2342.19200300.100.1.11","documentIdentifier" },
			{ "0.9.2342.19200300.100.1.12","documentTitle" },
			{ "0.9.2342.19200300.100.1.13","documentVersion" },
			{ "0.9.2342.19200300.100.1.14","documentAuthor" },
			{ "0.9.2342.19200300.100.1.15","documentLocation" },
			{ "0.9.2342.19200300.100.1.2","textEncodedORAddress" },
			{ "0.9.2342.19200300.100.1.20","homePhone" },
			{ "0.9.2342.19200300.100.1.21","secretary" },
			{ "0.9.2342.19200300.100.1.25","dc" },
			{ "0.9.2342.19200300.100.1.3","mail" },
			{ "0.9.2342.19200300.100.1.37","associatedDomain" },
			{ "0.9.2342.19200300.100.1.38","associatedName" },
			{ "0.9.2342.19200300.100.1.41","mobile" },
			{ "0.9.2342.19200300.100.1.42","pager" },
			{ "0.9.2342.19200300.100.1.44","uniqueIdentifier" },
			{ "0.9.2342.19200300.100.1.45","organizationalStatus" },
			{ "0.9.2342.19200300.100.1.48","buildingName" },
			{ "0.9.2342.19200300.100.1.5","drink" },
			{ "0.9.2342.19200300.100.1.55","audio" },
			{ "0.9.2342.19200300.100.1.56","documentPublisher" },
			{ "0.9.2342.19200300.100.1.6","roomNumber" },
			{ "0.9.2342.19200300.100.1.60","jpegPhoto" },
			{ "0.9.2342.19200300.100.1.7","photo" },
			{ "0.9.2342.19200300.100.1.8","userClass" },
			{ "0.9.2342.19200300.100.1.9","host" },
			{ "1.2.840.113549.1.9.2","unstructuredName" },
			{ "1.2.840.113549.1.9.8","unstructuredAddress" },
			{ "1.2.840.113556.1.2.1","instanceType" },
			{ "1.2.840.113556.1.2.102","memberOf" },
			{ "1.2.840.113556.1.2.104","ownerBL" },
			{ "1.2.840.113556.1.2.115","invocationId" },
			{ "1.2.840.113556.1.2.118","otherPager" },
			{ "1.2.840.113556.1.2.120","uSNChanged" },
			{ "1.2.840.113556.1.2.121","uSNLastObjRem" },
			{ "1.2.840.113556.1.2.13","displayName" },
			{ "1.2.840.113556.1.2.131","co" },
			{ "1.2.840.113556.1.2.135","cost" },
			{ "1.2.840.113556.1.2.14","hasMasterNCs" },
			{ "1.2.840.113556.1.2.141","department" },
			{ "1.2.840.113556.1.2.146","company" },
			{ "1.2.840.113556.1.2.15","hasPartialReplicaNCs" },
			{ "1.2.840.113556.1.2.16","nCName" },
			{ "1.2.840.113556.1.2.169","showInAdvancedViewOnly" },
			{ "1.2.840.113556.1.2.18","otherTelephone" },
			{ "1.2.840.113556.1.2.19","uSNCreated" },
			{ "1.2.840.113556.1.2.194","adminDisplayName" },
			{ "1.2.840.113556.1.2.2","whenCreated" },
			{ "1.2.840.113556.1.2.21","subClassOf" },
			{ "1.2.840.113556.1.2.210","proxyAddresses" },
			{ "1.2.840.113556.1.2.212","dSHeuristics" },
			{ "1.2.840.113556.1.2.214","originalDisplayTableMSDOS" },
			{ "1.2.840.113556.1.2.218","oMObjectClass" },
			{ "1.2.840.113556.1.2.22","governsID" },
			{ "1.2.840.113556.1.2.226","adminDescription" },
			{ "1.2.840.113556.1.2.227","extensionName" },
			{ "1.2.840.113556.1.2.231","oMSyntax" },
			{ "1.2.840.113556.1.2.24","mustContain" },
			{ "1.2.840.113556.1.2.25","mayContain" },
			{ "1.2.840.113556.1.2.255","addressSyntax" },
			{ "1.2.840.113556.1.2.256","streetAddress" },
			{ "1.2.840.113556.1.2.26","rDNAttID" },
			{ "1.2.840.113556.1.2.267","uSNDSALastObjRemoved" },
			{ "1.2.840.113556.1.2.277","otherHomePhone" },
			{ "1.2.840.113556.1.2.281","nTSecurityDescriptor" },
			{ "1.2.840.113556.1.2.3","whenChanged" },
			{ "1.2.840.113556.1.2.30","attributeID" },
			{ "1.2.840.113556.1.2.301","garbageCollPeriod" },
			{ "1.2.840.113556.1.2.32","attributeSyntax" },
			{ "1.2.840.113556.1.2.324","addressEntryDisplayTable" },
			{ "1.2.840.113556.1.2.325","perMsgDialogDisplayTable" },
			{ "1.2.840.113556.1.2.326","perRecipDialogDisplayTable" },
			{ "1.2.840.113556.1.2.327","helpFileName" },
			{ "1.2.840.113556.1.2.33","isSingleValued" },
			{ "1.2.840.113556.1.2.334","searchFlags" },
			{ "1.2.840.113556.1.2.34","rangeLower" },
			{ "1.2.840.113556.1.2.35","rangeUpper" },
			{ "1.2.840.113556.1.2.350","addressType" },
			{ "1.2.840.113556.1.2.351","auxiliaryClass" },
			{ "1.2.840.113556.1.2.353","displayNamePrintable" },
			{ "1.2.840.113556.1.2.36","dMDLocation" },
			{ "1.2.840.113556.1.2.370","objectClassCategory" },
			{ "1.2.840.113556.1.2.380","extendedCharsAllowed" },
			{ "1.2.840.113556.1.2.400","addressEntryDisplayTableMSDOS" },
			{ "1.2.840.113556.1.2.402","helpData16" },
			{ "1.2.840.113556.1.2.436","directReports" },
			{ "1.2.840.113556.1.2.444","msExchAssistantName" },
			{ "1.2.840.113556.1.2.445","originalDisplayTable" },
			{ "1.2.840.113556.1.2.459","networkAddress" },
			{ "1.2.840.113556.1.2.460","lDAPDisplayName" },
			{ "1.2.840.113556.1.2.464","wWWHomePage" },
			{ "1.2.840.113556.1.2.469","USNIntersite" },
			{ "1.2.840.113556.1.2.471","schemaVersion" },
			{ "1.2.840.113556.1.2.48","isDeleted" },
			{ "1.2.840.113556.1.2.49","mAPIID" },
			{ "1.2.840.113556.1.2.50","linkID" },
			{ "1.2.840.113556.1.2.523","proxyGenerationEnabled" },
			{ "1.2.840.113556.1.2.54","tombstoneLifetime" },
			{ "1.2.840.113556.1.2.557","Enabled" },
			{ "1.2.840.113556.1.2.593","msExchLabeledURI" },
			{ "1.2.840.113556.1.2.596","msExchHouseIdentifier" },
			{ "1.2.840.113556.1.2.598","dmdName" },
			{ "1.2.840.113556.1.2.610","employeeNumber" },
			{ "1.2.840.113556.1.2.613","employeeType" },
			{ "1.2.840.113556.1.2.615","personalTitle" },
			{ "1.2.840.113556.1.2.617","homePostalAddress" },
			{ "1.2.840.113556.1.2.7","subRefs" },
			{ "1.2.840.113556.1.2.74","dSASignature" },
			{ "1.2.840.113556.1.2.76","objectVersion" },
			{ "1.2.840.113556.1.2.8","possSuperiors" },
			{ "1.2.840.113556.1.2.81","info" },
			{ "1.2.840.113556.1.2.83","repsTo" },
			{ "1.2.840.113556.1.2.9","helpData32" },
			{ "1.2.840.113556.1.2.91","repsFrom" },
			{ "1.2.840.113556.1.4.1","name" },
			{ "1.2.840.113556.1.4.100","priorValue" },
			{ "1.2.840.113556.1.4.101","privateKey" },
			{ "1.2.840.113556.1.4.103","proxyLifetime" },
			{ "1.2.840.113556.1.4.105","remoteServerName" },
			{ "1.2.840.113556.1.4.107","remoteSource" },
			{ "1.2.840.113556.1.4.108","remoteSourceType" },
			{ "1.2.840.113556.1.4.109","replicaSource" },
			{ "1.2.840.113556.1.4.11","authenticationOptions" },
			{ "1.2.840.113556.1.4.1119","msNPAllowDialin" },
			{ "1.2.840.113556.1.4.1123","msNPCalledStationID" },
			{ "1.2.840.113556.1.4.1124","msNPCallingStationID" },
			{ "1.2.840.113556.1.4.113","rpcNsBindings" },
			{ "1.2.840.113556.1.4.1130","msNPSavedCallingStationID" },
			{ "1.2.840.113556.1.4.114","rpcNsGroup" },
			{ "1.2.840.113556.1.4.1145","msRADIUSCallbackNumber" },
			{ "1.2.840.113556.1.4.115","rpcNsInterfaceID" },
			{ "1.2.840.113556.1.4.1153","msRADIUSFramedIPAddress" },
			{ "1.2.840.113556.1.4.1158","msRADIUSFramedRoute" },
			{ "1.2.840.113556.1.4.117","rpcNsPriority" },
			{ "1.2.840.113556.1.4.1171","msRADIUSServiceType" },
			{ "1.2.840.113556.1.4.118","rpcNsProfileEntry" },
			{ "1.2.840.113556.1.4.1189","msRASSavedCallbackNumber" },
			{ "1.2.840.113556.1.4.1190","msRASSavedFramedIPAddress" },
			{ "1.2.840.113556.1.4.1191","msRASSavedFramedRoute" },
			{ "1.2.840.113556.1.4.12","badPwdCount" },
			{ "1.2.840.113556.1.4.120","schemaFlagsEx" },
			{ "1.2.840.113556.1.4.1208","aNR" },
			{ "1.2.840.113556.1.4.1209","shortServerName" },
			{ "1.2.840.113556.1.4.121","securityIdentifier" },
			{ "1.2.840.113556.1.4.1212","isEphemeral" },
			{ "1.2.840.113556.1.4.1213","assocNTAccount" },
			{ "1.2.840.113556.1.4.122","serviceClassID" },
			{ "1.2.840.113556.1.4.1224","parentGUID" },
			{ "1.2.840.113556.1.4.1225","mSMQPrevSiteGates" },
			{ "1.2.840.113556.1.4.1226","mSMQDependentClientServices" },
			{ "1.2.840.113556.1.4.1227","mSMQRoutingServices" },
			{ "1.2.840.113556.1.4.1228","mSMQDsServices" },
			{ "1.2.840.113556.1.4.123","serviceClassInfo" },
			{ "1.2.840.113556.1.4.1237","mSMQRoutingService" },
			{ "1.2.840.113556.1.4.1238","mSMQDsService" },
			{ "1.2.840.113556.1.4.1239","mSMQDependentClientService" },
			{ "1.2.840.113556.1.4.1240","netbootSIFFile" },
			{ "1.2.840.113556.1.4.1241","netbootMirrorDataFile" },
			{ "1.2.840.113556.1.4.1242","dNReferenceUpdate" },
			{ "1.2.840.113556.1.4.1243","mSMQQueueNameExt" },
			{ "1.2.840.113556.1.4.1244","addressBookRoots" },
			{ "1.2.840.113556.1.4.1245","globalAddressList" },
			{ "1.2.840.113556.1.4.1246","interSiteTopologyGenerator" },
			{ "1.2.840.113556.1.4.1247","interSiteTopologyRenew" },
			{ "1.2.840.113556.1.4.1248","interSiteTopologyFailover" },
			{ "1.2.840.113556.1.4.1249","proxiedObjectName" },
			{ "1.2.840.113556.1.4.125","supplementalCredentials" },
			{ "1.2.840.113556.1.4.129","trustAuthIncoming" },
			{ "1.2.840.113556.1.4.13","builtinCreationTime" },
			{ "1.2.840.113556.1.4.1301","tokenGroups" },
			{ "1.2.840.113556.1.4.1303","tokenGroupsNoGCAcceptable" },
			{ "1.2.840.113556.1.4.1304","sDRightsEffective" },
			{ "1.2.840.113556.1.4.1305","moveTreeState" },
			{ "1.2.840.113556.1.4.1306","dNSProperty" },
			{ "1.2.840.113556.1.4.1307","accountNameHistory" },
			{ "1.2.840.113556.1.4.1308","mSMQInterval1" },
			{ "1.2.840.113556.1.4.1309","mSMQInterval2" },
			{ "1.2.840.113556.1.4.1310","mSMQSiteGatesMig" },
			{ "1.2.840.113556.1.4.1311","printDuplexSupported" },
			{ "1.2.840.113556.1.4.1312","aCSServerList" },
			{ "1.2.840.113556.1.4.1313","aCSMaxTokenBucketPerFlow" },
			{ "1.2.840.113556.1.4.1314","aCSMaximumSDUSize" },
			{ "1.2.840.113556.1.4.1315","aCSMinimumPolicedSize" },
			{ "1.2.840.113556.1.4.1316","aCSMinimumLatency" },
			{ "1.2.840.113556.1.4.1317","aCSMinimumDelayVariation" },
			{ "1.2.840.113556.1.4.1318","aCSNonReservedPeakRate" },
			{ "1.2.840.113556.1.4.1319","aCSNonReservedTokenSize" },
			{ "1.2.840.113556.1.4.132","trustDirection" },
			{ "1.2.840.113556.1.4.1320","aCSNonReservedMaxSDUSize" },
			{ "1.2.840.113556.1.4.1321","aCSNonReservedMinPolicedSize" },
			{ "1.2.840.113556.1.4.1327","pKIDefaultKeySpec" },
			{ "1.2.840.113556.1.4.1328","pKIKeyUsage" },
			{ "1.2.840.113556.1.4.1329","pKIMaxIssuingDepth" },
			{ "1.2.840.113556.1.4.133","trustPartner" },
			{ "1.2.840.113556.1.4.1330","pKICriticalExtensions" },
			{ "1.2.840.113556.1.4.1331","pKIExpirationPeriod" },
			{ "1.2.840.113556.1.4.1332","pKIOverlapPeriod" },
			{ "1.2.840.113556.1.4.1333","pKIExtendedKeyUsage" },
			{ "1.2.840.113556.1.4.1334","pKIDefaultCSPs" },
			{ "1.2.840.113556.1.4.1335","pKIEnrollmentAccess" },
			{ "1.2.840.113556.1.4.1336","replInterval" },
			{ "1.2.840.113556.1.4.1337","mSMQUserSid" },
			{ "1.2.840.113556.1.4.134","trustPosixOffset" },
			{ "1.2.840.113556.1.4.1343","dSUIAdminNotification" },
			{ "1.2.840.113556.1.4.1344","dSUIAdminMaximum" },
			{ "1.2.840.113556.1.4.1345","dSUIShellMaximum" },
			{ "1.2.840.113556.1.4.1346","templateRoots" },
			{ "1.2.840.113556.1.4.1347","sPNMappings" },
			{ "1.2.840.113556.1.4.1348","gPCMachineExtensionNames" },
			{ "1.2.840.113556.1.4.1349","gPCUserExtensionNames" },
			{ "1.2.840.113556.1.4.135","trustAuthOutgoing" },
			{ "1.2.840.113556.1.4.1353","localizationDisplayId" },
			{ "1.2.840.113556.1.4.1354","scopeFlags" },
			{ "1.2.840.113556.1.4.1355","queryFilter" },
			{ "1.2.840.113556.1.4.1356","validAccesses" },
			{ "1.2.840.113556.1.4.1357","dSCorePropagationData" },
			{ "1.2.840.113556.1.4.1358","schemaInfo" },
			{ "1.2.840.113556.1.4.1359","otherWellKnownObjects" },
			{ "1.2.840.113556.1.4.136","trustType" },
			{ "1.2.840.113556.1.4.1360","mS-DS-ConsistencyGuid" },
			{ "1.2.840.113556.1.4.1361","mS-DS-ConsistencyChildCount" },
			{ "1.2.840.113556.1.4.1363","mS-SQL-Name" },
			{ "1.2.840.113556.1.4.1364","mS-SQL-RegisteredOwner" },
			{ "1.2.840.113556.1.4.1365","mS-SQL-Contact" },
			{ "1.2.840.113556.1.4.1366","mS-SQL-Location" },
			{ "1.2.840.113556.1.4.1367","mS-SQL-Memory" },
			{ "1.2.840.113556.1.4.1368","mS-SQL-Build" },
			{ "1.2.840.113556.1.4.1369","mS-SQL-ServiceAccount" },
			{ "1.2.840.113556.1.4.137","uNCName" },
			{ "1.2.840.113556.1.4.1370","mS-SQL-CharacterSet" },
			{ "1.2.840.113556.1.4.1371","mS-SQL-SortOrder" },
			{ "1.2.840.113556.1.4.1372","mS-SQL-UnicodeSortOrder" },
			{ "1.2.840.113556.1.4.1373","mS-SQL-Clustered" },
			{ "1.2.840.113556.1.4.1374","mS-SQL-NamedPipe" },
			{ "1.2.840.113556.1.4.1375","mS-SQL-MultiProtocol" },
			{ "1.2.840.113556.1.4.1376","mS-SQL-SPX" },
			{ "1.2.840.113556.1.4.1377","mS-SQL-TCPIP" },
			{ "1.2.840.113556.1.4.1378","mS-SQL-AppleTalk" },
			{ "1.2.840.113556.1.4.1379","mS-SQL-Vines" },
			{ "1.2.840.113556.1.4.138","userParameters" },
			{ "1.2.840.113556.1.4.1380","mS-SQL-Status" },
			{ "1.2.840.113556.1.4.1381","mS-SQL-LastUpdatedDate" },
			{ "1.2.840.113556.1.4.1382","mS-SQL-InformationURL" },
			{ "1.2.840.113556.1.4.1383","mS-SQL-ConnectionURL" },
			{ "1.2.840.113556.1.4.1384","mS-SQL-PublicationURL" },
			{ "1.2.840.113556.1.4.1385","mS-SQL-GPSLatitude" },
			{ "1.2.840.113556.1.4.1386","mS-SQL-GPSLongitude" },
			{ "1.2.840.113556.1.4.1387","mS-SQL-GPSHeight" },
			{ "1.2.840.113556.1.4.1388","mS-SQL-Version" },
			{ "1.2.840.113556.1.4.1389","mS-SQL-Language" },
			{ "1.2.840.113556.1.4.139","profilePath" },
			{ "1.2.840.113556.1.4.1390","mS-SQL-Description" },
			{ "1.2.840.113556.1.4.1391","mS-SQL-Type" },
			{ "1.2.840.113556.1.4.1392","mS-SQL-InformationDirectory" },
			{ "1.2.840.113556.1.4.1393","mS-SQL-Database" },
			{ "1.2.840.113556.1.4.1394","mS-SQL-AllowAnonymousSubscription" },
			{ "1.2.840.113556.1.4.1395","mS-SQL-Alias" },
			{ "1.2.840.113556.1.4.1396","mS-SQL-Size" },
			{ "1.2.840.113556.1.4.1397","mS-SQL-CreationDate" },
			{ "1.2.840.113556.1.4.1398","mS-SQL-LastBackupDate" },
			{ "1.2.840.113556.1.4.1399","mS-SQL-LastDiagnosticDate" },
			{ "1.2.840.113556.1.4.14","builtinModifiedCount" },
			{ "1.2.840.113556.1.4.1400","mS-SQL-Applications" },
			{ "1.2.840.113556.1.4.1401","mS-SQL-Keywords" },
			{ "1.2.840.113556.1.4.1402","mS-SQL-Publisher" },
			{ "1.2.840.113556.1.4.1403","mS-SQL-AllowKnownPullSubscription" },
			{ "1.2.840.113556.1.4.1404","mS-SQL-AllowImmediateUpdatingSubscription" },
			{ "1.2.840.113556.1.4.1405","mS-SQL-AllowQueuedUpdatingSubscription" },
			{ "1.2.840.113556.1.4.1406","mS-SQL-AllowSnapshotFilesFTPDownloading" },
			{ "1.2.840.113556.1.4.1407","mS-SQL-ThirdParty" },
			{ "1.2.840.113556.1.4.1408","mS-DS-ReplicatesNCReason" },
			{ "1.2.840.113556.1.4.1409","masteredBy" },
			{ "1.2.840.113556.1.4.141","versionNumber" },
			{ "1.2.840.113556.1.4.1410","mS-DS-CreatorSID" },
			{ "1.2.840.113556.1.4.1411","ms-DS-MachineAccountQuota" },
			{ "1.2.840.113556.1.4.1412","primaryGroupToken" },
			{ "1.2.840.113556.1.4.1414","dNSTombstoned" },
			{ "1.2.840.113556.1.4.1415","mSMQLabelEx" },
			{ "1.2.840.113556.1.4.1416","mSMQSiteNameEx" },
			{ "1.2.840.113556.1.4.1417","mSMQComputerTypeEx" },
			{ "1.2.840.113556.1.4.1418","tokenGroupsGlobalAndUniversal" },
			{ "1.2.840.113556.1.4.142","winsockAddresses" },
			{ "1.2.840.113556.1.4.1423","msCOM-PartitionLink" },
			{ "1.2.840.113556.1.4.1424","msCOM-PartitionSetLink" },
			{ "1.2.840.113556.1.4.1425","msCOM-UserLink" },
			{ "1.2.840.113556.1.4.1426","msCOM-UserPartitionSetLink" },
			{ "1.2.840.113556.1.4.1427","msCOM-DefaultPartitionLink" },
			{ "1.2.840.113556.1.4.1428","msCOM-ObjectId" },
			{ "1.2.840.113556.1.4.1429","msPKI-RA-Signature" },
			{ "1.2.840.113556.1.4.1430","msPKI-Enrollment-Flag" },
			{ "1.2.840.113556.1.4.1431","msPKI-Private-Key-Flag" },
			{ "1.2.840.113556.1.4.1432","msPKI-Certificate-Name-Flag" },
			{ "1.2.840.113556.1.4.1433","msPKI-Minimal-Key-Size" },
			{ "1.2.840.113556.1.4.1434","msPKI-Template-Schema-Version" },
			{ "1.2.840.113556.1.4.1435","msPKI-Template-Minor-Revision" },
			{ "1.2.840.113556.1.4.1436","msPKI-Cert-Template-OID" },
			{ "1.2.840.113556.1.4.1437","msPKI-Supersede-Templates" },
			{ "1.2.840.113556.1.4.1438","msPKI-RA-Policies" },
			{ "1.2.840.113556.1.4.1439","msPKI-Certificate-Policy" },
			{ "1.2.840.113556.1.4.144","operatorCount" },
			{ "1.2.840.113556.1.4.1440","msDs-Schema-Extensions" },
			{ "1.2.840.113556.1.4.1441","msDS-Cached-Membership" },
			{ "1.2.840.113556.1.4.1442","msDS-Cached-Membership-Time-Stamp" },
			{ "1.2.840.113556.1.4.1443","msDS-Site-Affinity" },
			{ "1.2.840.113556.1.4.1444","msDS-Preferred-GC-Site" },
			{ "1.2.840.113556.1.4.145","revision" },
			{ "1.2.840.113556.1.4.1458","msDS-Auxiliary-Classes" },
			{ "1.2.840.113556.1.4.1459","msDS-Behavior-Version" },
			{ "1.2.840.113556.1.4.146","objectSid" },
			{ "1.2.840.113556.1.4.1460","msDS-User-Account-Control-Computed" },
			{ "1.2.840.113556.1.4.148","schemaIDGUID" },
			{ "1.2.840.113556.1.4.149","attributeSecurityGUID" },
			{ "1.2.840.113556.1.4.15","msiScriptPath" },
			{ "1.2.840.113556.1.4.150","adminCount" },
			{ "1.2.840.113556.1.4.151","oEMInformation" },
			{ "1.2.840.113556.1.4.152","groupAttributes" },
			{ "1.2.840.113556.1.4.153","rid" },
			{ "1.2.840.113556.1.4.154","serverState" },
			{ "1.2.840.113556.1.4.155","uASCompat" },
			{ "1.2.840.113556.1.4.156","comment" },
			{ "1.2.840.113556.1.4.157","serverRole" },
			{ "1.2.840.113556.1.4.158","domainReplica" },
			{ "1.2.840.113556.1.4.159","accountExpires" },
			{ "1.2.840.113556.1.4.16","codePage" },
			{ "1.2.840.113556.1.4.160","lmPwdHistory" },
			{ "1.2.840.113556.1.4.1621","msDS-Other-Settings" },
			{ "1.2.840.113556.1.4.1622","msDS-Entry-Time-To-Die" },
			{ "1.2.840.113556.1.4.1623","msWMI-Author" },
			{ "1.2.840.113556.1.4.1624","msWMI-ChangeDate" },
			{ "1.2.840.113556.1.4.1625","msWMI-ClassDefinition" },
			{ "1.2.840.113556.1.4.1626","msWMI-CreationDate" },
			{ "1.2.840.113556.1.4.1627","msWMI-ID" },
			{ "1.2.840.113556.1.4.1628","msWMI-IntDefault" },
			{ "1.2.840.113556.1.4.1629","msWMI-IntMax" },
			{ "1.2.840.113556.1.4.1630","msWMI-IntMin" },
			{ "1.2.840.113556.1.4.1631","msWMI-IntValidValues" },
			{ "1.2.840.113556.1.4.1632","msWMI-Int8Default" },
			{ "1.2.840.113556.1.4.1633","msWMI-Int8Max" },
			{ "1.2.840.113556.1.4.1634","msWMI-Int8Min" },
			{ "1.2.840.113556.1.4.1635","msWMI-Int8ValidValues" },
			{ "1.2.840.113556.1.4.1636","msWMI-StringDefault" },
			{ "1.2.840.113556.1.4.1637","msWMI-StringValidValues" },
			{ "1.2.840.113556.1.4.1638","msWMI-Mof" },
			{ "1.2.840.113556.1.4.1639","msWMI-Name" },
			{ "1.2.840.113556.1.4.1640","msWMI-NormalizedClass" },
			{ "1.2.840.113556.1.4.1641","msWMI-PropertyName" },
			{ "1.2.840.113556.1.4.1642","msWMI-Query" },
			{ "1.2.840.113556.1.4.1643","msWMI-QueryLanguage" },
			{ "1.2.840.113556.1.4.1644","msWMI-SourceOrganization" },
			{ "1.2.840.113556.1.4.1645","msWMI-TargetClass" },
			{ "1.2.840.113556.1.4.1646","msWMI-TargetNameSpace" },
			{ "1.2.840.113556.1.4.1647","msWMI-TargetObject" },
			{ "1.2.840.113556.1.4.1648","msWMI-TargetPath" },
			{ "1.2.840.113556.1.4.1649","msWMI-TargetType" },
			{ "1.2.840.113556.1.4.166","groupMembershipSAM" },
			{ "1.2.840.113556.1.4.1661","msDS-NC-Replica-Locations" },
			{ "1.2.840.113556.1.4.1663","msDS-Replication-Notify-First-DSA-Delay" },
			{ "1.2.840.113556.1.4.1664","msDS-Replication-Notify-Subsequent-DSA-Delay" },
			{ "1.2.840.113556.1.4.1669","msDS-Approx-Immed-Subordinates" },
			{ "1.2.840.113556.1.4.1671","msPKI-OID-Attribute" },
			{ "1.2.840.113556.1.4.1672","msPKI-OID-CPS" },
			{ "1.2.840.113556.1.4.1673","msPKI-OID-User-Notice" },
			{ "1.2.840.113556.1.4.1674","msPKI-Certificate-Application-Policy" },
			{ "1.2.840.113556.1.4.1675","msPKI-RA-Application-Policies" },
			{ "1.2.840.113556.1.4.1676","msWMI-Class" },
			{ "1.2.840.113556.1.4.1677","msWMI-Genus" },
			{ "1.2.840.113556.1.4.1678","msWMI-intFlags1" },
			{ "1.2.840.113556.1.4.1679","msWMI-intFlags2" },
			{ "1.2.840.113556.1.4.168","modifiedCount" },
			{ "1.2.840.113556.1.4.1680","msWMI-intFlags3" },
			{ "1.2.840.113556.1.4.1681","msWMI-intFlags4" },
			{ "1.2.840.113556.1.4.1682","msWMI-Parm1" },
			{ "1.2.840.113556.1.4.1683","msWMI-Parm2" },
			{ "1.2.840.113556.1.4.1684","msWMI-Parm3" },
			{ "1.2.840.113556.1.4.1685","msWMI-Parm4" },
			{ "1.2.840.113556.1.4.1686","msWMI-ScopeGuid" },
			{ "1.2.840.113556.1.4.1687","extraColumns" },
			{ "1.2.840.113556.1.4.1688","msDS-Security-Group-Extra-Classes" },
			{ "1.2.840.113556.1.4.1689","msDS-Non-Security-Group-Extra-Classes" },
			{ "1.2.840.113556.1.4.169","logonCount" },
			{ "1.2.840.113556.1.4.1690","adminMultiselectPropertyPages" },
			{ "1.2.840.113556.1.4.1692","msFRS-Topology-Pref" },
			{ "1.2.840.113556.1.4.1693","msFRS-Hub-Member" },
			{ "1.2.840.113556.1.4.1694","gPCWQLFilter" },
			{ "1.2.840.113556.1.4.1695","msMQ-Recipient-FormatName" },
			{ "1.2.840.113556.1.4.1696","lastLogonTimestamp" },
			{ "1.2.840.113556.1.4.1697","msDS-Settings" },
			{ "1.2.840.113556.1.4.1698","msTAPI-uid" },
			{ "1.2.840.113556.1.4.1699","msTAPI-ProtocolId" },
			{ "1.2.840.113556.1.4.170","systemOnly" },
			{ "1.2.840.113556.1.4.1700","msTAPI-ConferenceBlob" },
			{ "1.2.840.113556.1.4.1701","msTAPI-IpAddress" },
			{ "1.2.840.113556.1.4.1702","msDS-TrustForestTrustInfo" },
			{ "1.2.840.113556.1.4.1703","msDS-FilterContainers" },
			{ "1.2.840.113556.1.4.1704","msDS-NCReplCursors" },
			{ "1.2.840.113556.1.4.1705","msDS-NCReplInboundNeighbors" },
			{ "1.2.840.113556.1.4.1706","msDS-NCReplOutboundNeighbors" },
			{ "1.2.840.113556.1.4.1707","msDS-ReplAttributeMetaData" },
			{ "1.2.840.113556.1.4.1708","msDS-ReplValueMetaData" },
			{ "1.2.840.113556.1.4.1709","msDS-HasInstantiatedNCs" },
			{ "1.2.840.113556.1.4.1710","msDS-AllowedDNSSuffixes" },
			{ "1.2.840.113556.1.4.1711","msDS-SDReferenceDomain" },
			{ "1.2.840.113556.1.4.1712","msPKI-OIDLocalizedName" },
			{ "1.2.840.113556.1.4.1713","MSMQ-SecuredSource" },
			{ "1.2.840.113556.1.4.1714","MSMQ-MulticastAddress" },
			{ "1.2.840.113556.1.4.1715","msDS-SPNSuffixes" },
			{ "1.2.840.113556.1.4.1716","msDS-IntId" },
			{ "1.2.840.113556.1.4.1717","msDS-AdditionalDnsHostName" },
			{ "1.2.840.113556.1.4.1718","msDS-AdditionalSamAccountName" },
			{ "1.2.840.113556.1.4.1719","msDS-DnsRootAlias" },
			{ "1.2.840.113556.1.4.1720","msDS-ReplicationEpoch" },
			{ "1.2.840.113556.1.4.1721","msDS-UpdateScript" },
			{ "1.2.840.113556.1.4.1780","hideFromAB" },
			{ "1.2.840.113556.1.4.1782","msDS-KeyVersionNumber" },
			{ "1.2.840.113556.1.4.1783","msDS-ExecuteScriptPassword" },
			{ "1.2.840.113556.1.4.1784","msDS-LogonTimeSyncInterval" },
			{ "1.2.840.113556.1.4.1785","msIIS-FTPRoot" },
			{ "1.2.840.113556.1.4.1786","msIIS-FTPDir" },
			{ "1.2.840.113556.1.4.1787","msDS-AllowedToDelegateTo" },
			{ "1.2.840.113556.1.4.1788","msDS-PerUserTrustQuota" },
			{ "1.2.840.113556.1.4.1789","msDS-AllUsersTrustQuota" },
			{ "1.2.840.113556.1.4.1790","msDS-PerUserTrustTombstonesQuota" },
			{ "1.2.840.113556.1.4.1792","msDS-AzLDAPQuery" },
			{ "1.2.840.113556.1.4.1793","msDS-NonMembers" },
			{ "1.2.840.113556.1.4.1794","msDS-NonMembersBL" },
			{ "1.2.840.113556.1.4.1795","msDS-AzDomainTimeout" },
			{ "1.2.840.113556.1.4.1796","msDS-AzScriptEngineCacheMax" },
			{ "1.2.840.113556.1.4.1797","msDS-AzScriptTimeout" },
			{ "1.2.840.113556.1.4.1798","msDS-AzApplicationName" },
			{ "1.2.840.113556.1.4.1799","msDS-AzScopeName" },
			{ "1.2.840.113556.1.4.1800","msDS-AzOperationID" },
			{ "1.2.840.113556.1.4.1801","msDS-AzBizRule" },
			{ "1.2.840.113556.1.4.1802","msDS-AzBizRuleLanguage" },
			{ "1.2.840.113556.1.4.1803","msDS-AzLastImportedBizRulePath" },
			{ "1.2.840.113556.1.4.1805","msDS-AzGenerateAudits" },
			{ "1.2.840.113556.1.4.1806","msDS-MembersForAzRole" },
			{ "1.2.840.113556.1.4.1807","msDS-MembersForAzRoleBL" },
			{ "1.2.840.113556.1.4.1808","msDS-OperationsForAzTask" },
			{ "1.2.840.113556.1.4.1809","msDS-OperationsForAzTaskBL" },
			{ "1.2.840.113556.1.4.1810","msDS-TasksForAzTask" },
			{ "1.2.840.113556.1.4.1811","msDS-TasksForAzTaskBL" },
			{ "1.2.840.113556.1.4.1812","msDS-OperationsForAzRole" },
			{ "1.2.840.113556.1.4.1813","msDS-OperationsForAzRoleBL" },
			{ "1.2.840.113556.1.4.1814","msDS-TasksForAzRole" },
			{ "1.2.840.113556.1.4.1815","msDS-TasksForAzRoleBL" },
			{ "1.2.840.113556.1.4.1816","msDS-AzClassId" },
			{ "1.2.840.113556.1.4.1817","msDS-AzApplicationVersion" },
			{ "1.2.840.113556.1.4.1818","msDS-AzTaskIsRoleDefinition" },
			{ "1.2.840.113556.1.4.1819","msDS-AzApplicationData" },
			{ "1.2.840.113556.1.4.1820","msDS-HasDomainNCs" },
			{ "1.2.840.113556.1.4.1821","msieee80211-Data" },
			{ "1.2.840.113556.1.4.1822","msieee80211-DataType" },
			{ "1.2.840.113556.1.4.1823","msieee80211-ID" },
			{ "1.2.840.113556.1.4.1824","msDS-AzMajorVersion" },
			{ "1.2.840.113556.1.4.1825","msDS-AzMinorVersion" },
			{ "1.2.840.113556.1.4.1826","msDS-RetiredReplNCSignatures" },
			{ "1.2.840.113556.1.4.1831","msDS-ByteArray" },
			{ "1.2.840.113556.1.4.1832","msDS-DateTime" },
			{ "1.2.840.113556.1.4.1833","msDS-ExternalKey" },
			{ "1.2.840.113556.1.4.1834","msDS-ExternalStore" },
			{ "1.2.840.113556.1.4.1835","msDS-Integer" },
			{ "1.2.840.113556.1.4.1836","msDS-hasMasterNCs" },
			{ "1.2.840.113556.1.4.1837","msDs-masteredBy" },
			{ "1.2.840.113556.1.4.1840","msDS-ObjectReference" },
			{ "1.2.840.113556.1.4.1841","msDS-ObjectReferenceBL" },
			{ "1.2.840.113556.1.4.1842","msDs-MaxValues" },
			{ "1.2.840.113556.1.4.1843","msDRM-IdentityCertificate" },
			{ "1.2.840.113556.1.4.1844","msDS-QuotaTrustee" },
			{ "1.2.840.113556.1.4.1845","msDS-QuotaAmount" },
			{ "1.2.840.113556.1.4.1846","msDS-DefaultQuota" },
			{ "1.2.840.113556.1.4.1847","msDS-TombstoneQuotaFactor" },
			{ "1.2.840.113556.1.4.1848","msDS-QuotaEffective" },
			{ "1.2.840.113556.1.4.1849","msDS-QuotaUsed" },
			{ "1.2.840.113556.1.4.1850","msDS-TopQuotaUsage" },
			{ "1.2.840.113556.1.4.1853","msDS-UserAccountDisabled" },
			{ "1.2.840.113556.1.4.1854","ms-DS-UserPasswordNotRequired" },
			{ "1.2.840.113556.1.4.1855","msDS-UserDontExpirePassword" },
			{ "1.2.840.113556.1.4.1856","ms-DS-UserEncryptedTextPasswordAllowed" },
			{ "1.2.840.113556.1.4.1857","ms-DS-UserAccountAutoLocked" },
			{ "1.2.840.113556.1.4.1858","msDS-UserPasswordExpired" },
			{ "1.2.840.113556.1.4.1859","msDS-PortLDAP" },
			{ "1.2.840.113556.1.4.1860","msDS-PortSSL" },
			{ "1.2.840.113556.1.4.1861","msDS-ReplAuthenticationMode" },
			{ "1.2.840.113556.1.4.1862","msDS-ServiceAccountDNSDomain" },
			{ "1.2.840.113556.1.4.1865","msDS-PrincipalName" },
			{ "1.2.840.113556.1.4.1866","msDS-ServiceAccount" },
			{ "1.2.840.113556.1.4.1867","msDS-ServiceAccountBL" },
			{ "1.2.840.113556.1.4.1870","msDS-DisableForInstances" },
			{ "1.2.840.113556.1.4.1871","msDS-DisableForInstancesBL" },
			{ "1.2.840.113556.1.4.1872","msDS-SCPContainer" },
			{ "1.2.840.113556.1.4.1879","msDS-SourceObjectDN" },
			{ "1.2.840.113556.1.4.1892","msPKIRoamingTimeStamp" },
			{ "1.2.840.113556.1.4.1893","msPKIDPAPIMasterKeys" },
			{ "1.2.840.113556.1.4.1894","msPKIAccountCredentials" },
			{ "1.2.840.113556.1.4.19","cOMClassID" },
			{ "1.2.840.113556.1.4.1910","unixUserPassword" },
			{ "1.2.840.113556.1.4.1913","msRADIUS-FramedInterfaceId" },
			{ "1.2.840.113556.1.4.1914","msRADIUS-SavedFramedInterfaceId" },
			{ "1.2.840.113556.1.4.1915","msRADIUS-FramedIpv6Prefix" },
			{ "1.2.840.113556.1.4.1916","msRADIUS-SavedFramedIpv6Prefix" },
			{ "1.2.840.113556.1.4.1917","msRADIUS-FramedIpv6Route" },
			{ "1.2.840.113556.1.4.1918","msRADIUS-SavedFramedIpv6Route" },
			{ "1.2.840.113556.1.4.1923","msDS-KrbTgtLink" },
			{ "1.2.840.113556.1.4.1924","msDS-RevealedUsers" },
			{ "1.2.840.113556.1.4.1925","msDS-hasFullReplicaNCs" },
			{ "1.2.840.113556.1.4.1926","msDS-NeverRevealGroup" },
			{ "1.2.840.113556.1.4.1928","msDS-RevealOnDemandGroup" },
			{ "1.2.840.113556.1.4.1929","msDS-SecondaryKrbTgtNumber" },
			{ "1.2.840.113556.1.4.1930","msDS-RevealedDSAs" },
			{ "1.2.840.113556.1.4.1931","msDS-KrbTgtLinkBl" },
			{ "1.2.840.113556.1.4.1932","msDS-IsFullReplicaFor" },
			{ "1.2.840.113556.1.4.1933","msDS-IsDomainFor" },
			{ "1.2.840.113556.1.4.1934","msDS-IsPartialReplicaFor" },
			{ "1.2.840.113556.1.4.1940","msDS-RevealedList" },
			{ "1.2.840.113556.1.4.1942","msDS-PhoneticFirstName" },
			{ "1.2.840.113556.1.4.1943","msDS-PhoneticLastName" },
			{ "1.2.840.113556.1.4.1944","msDS-PhoneticDepartment" },
			{ "1.2.840.113556.1.4.1945","msDS-PhoneticCompanyName" },
			{ "1.2.840.113556.1.4.1946","msDS-PhoneticDisplayName" },
			{ "1.2.840.113556.1.4.1947","msDS-SeniorityIndex" },
			{ "1.2.840.113556.1.4.1949","msDS-AzObjectGuid" },
			{ "1.2.840.113556.1.4.195","systemPossSuperiors" },
			{ "1.2.840.113556.1.4.1950","msDS-AzGenericData" },
			{ "1.2.840.113556.1.4.1951","ms-net-ieee-80211-GP-PolicyGUID" },
			{ "1.2.840.113556.1.4.1952","ms-net-ieee-80211-GP-PolicyData" },
			{ "1.2.840.113556.1.4.1953","ms-net-ieee-80211-GP-PolicyReserved" },
			{ "1.2.840.113556.1.4.1954","ms-net-ieee-8023-GP-PolicyGUID" },
			{ "1.2.840.113556.1.4.1955","ms-net-ieee-8023-GP-PolicyData" },
			{ "1.2.840.113556.1.4.1956","ms-net-ieee-8023-GP-PolicyReserved" },
			{ "1.2.840.113556.1.4.1957","msDS-AuthenticatedToAccountlist" },
			{ "1.2.840.113556.1.4.1958","msDS-AuthenticatedAtDC" },
			{ "1.2.840.113556.1.4.1959","msDS-isGC" },
			{ "1.2.840.113556.1.4.196","systemMayContain" },
			{ "1.2.840.113556.1.4.1960","msDS-isRODC" },
			{ "1.2.840.113556.1.4.1961","msDS-SiteName" },
			{ "1.2.840.113556.1.4.1962","msDS-PromotionSettings" },
			{ "1.2.840.113556.1.4.1963","msDS-SupportedEncryptionTypes" },
			{ "1.2.840.113556.1.4.1964","msFVE-RecoveryPassword" },
			{ "1.2.840.113556.1.4.1965","msFVE-RecoveryGuid" },
			{ "1.2.840.113556.1.4.1966","msTPM-OwnerInformation" },
			{ "1.2.840.113556.1.4.1967","msDS-NC-RO-Replica-Locations" },
			{ "1.2.840.113556.1.4.1968","msDS-NC-RO-Replica-Locations-BL" },
			{ "1.2.840.113556.1.4.1969","samDomainUpdates" },
			{ "1.2.840.113556.1.4.197","systemMustContain" },
			{ "1.2.840.113556.1.4.1970","msDS-LastSuccessfulInteractiveLogonTime" },
			{ "1.2.840.113556.1.4.1971","msDS-LastFailedInteractiveLogonTime" },
			{ "1.2.840.113556.1.4.1972","msDS-FailedInteractiveLogonCount" },
			{ "1.2.840.113556.1.4.1973","msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon" },
			{ "1.2.840.113556.1.4.1975","msDS-RevealedListBL" },
			{ "1.2.840.113556.1.4.1976","msTSProfilePath" },
			{ "1.2.840.113556.1.4.1977","msTSHomeDirectory" },
			{ "1.2.840.113556.1.4.1978","msTSHomeDrive" },
			{ "1.2.840.113556.1.4.1979","msTSAllowLogon" },
			{ "1.2.840.113556.1.4.198","systemAuxiliaryClass" },
			{ "1.2.840.113556.1.4.1980","msTSRemoteControl" },
			{ "1.2.840.113556.1.4.1981","msTSMaxDisconnectionTime" },
			{ "1.2.840.113556.1.4.1982","msTSMaxConnectionTime" },
			{ "1.2.840.113556.1.4.1983","msTSMaxIdleTime" },
			{ "1.2.840.113556.1.4.1984","msTSReconnectionAction" },
			{ "1.2.840.113556.1.4.1985","msTSBrokenConnectionAction" },
			{ "1.2.840.113556.1.4.1986","msTSConnectClientDrives" },
			{ "1.2.840.113556.1.4.1987","msTSConnectPrinterDrives" },
			{ "1.2.840.113556.1.4.1988","msTSDefaultToMainPrinter" },
			{ "1.2.840.113556.1.4.1989","msTSWorkDirectory" },
			{ "1.2.840.113556.1.4.199","serviceInstanceVersion" },
			{ "1.2.840.113556.1.4.1990","msTSInitialProgram" },
			{ "1.2.840.113556.1.4.1991","msTSProperty01" },
			{ "1.2.840.113556.1.4.1992","msTSProperty02" },
			{ "1.2.840.113556.1.4.1993","msTSExpireDate" },
			{ "1.2.840.113556.1.4.1994","msTSLicenseVersion" },
			{ "1.2.840.113556.1.4.1995","msTSManagingLS" },
			{ "1.2.840.113556.1.4.1996","msDS-UserPasswordExpiryTimeComputed" },
			{ "1.2.840.113556.1.4.1997","msDS-HABSeniorityIndex" },
			{ "1.2.840.113556.1.4.1998","msFVE-VolumeGuid" },
			{ "1.2.840.113556.1.4.1999","msFVE-KeyPackage" },
			{ "1.2.840.113556.1.4.2","objectGUID" },
			{ "1.2.840.113556.1.4.20","cOMInterfaceID" },
			{ "1.2.840.113556.1.4.200","controlAccessRights" },
			{ "1.2.840.113556.1.4.2000","msTSExpireDate2" },
			{ "1.2.840.113556.1.4.2001","msTSLicenseVersion2" },
			{ "1.2.840.113556.1.4.2002","msTSManagingLS2" },
			{ "1.2.840.113556.1.4.2003","msTSExpireDate3" },
			{ "1.2.840.113556.1.4.2004","msTSLicenseVersion3" },
			{ "1.2.840.113556.1.4.2005","msTSManagingLS3" },
			{ "1.2.840.113556.1.4.2006","msTSExpireDate4" },
			{ "1.2.840.113556.1.4.2007","msTSLicenseVersion4" },
			{ "1.2.840.113556.1.4.2008","msTSManagingLS4" },
			{ "1.2.840.113556.1.4.2009","msTSLSProperty01" },
			{ "1.2.840.113556.1.4.2010","msTSLSProperty02" },
			{ "1.2.840.113556.1.4.2011","msDS-MaximumPasswordAge" },
			{ "1.2.840.113556.1.4.2012","msDS-MinimumPasswordAge" },
			{ "1.2.840.113556.1.4.2013","msDS-MinimumPasswordLength" },
			{ "1.2.840.113556.1.4.2014","msDS-PasswordHistoryLength" },
			{ "1.2.840.113556.1.4.2015","msDS-PasswordComplexityEnabled" },
			{ "1.2.840.113556.1.4.2016","msDS-PasswordReversibleEncryptionEnabled" },
			{ "1.2.840.113556.1.4.2017","msDS-LockoutObservationWindow" },
			{ "1.2.840.113556.1.4.2018","msDS-LockoutDuration" },
			{ "1.2.840.113556.1.4.2019","msDS-LockoutThreshold" },
			{ "1.2.840.113556.1.4.202","auditingPolicy" },
			{ "1.2.840.113556.1.4.2020","msDS-PSOAppliesTo" },
			{ "1.2.840.113556.1.4.2021","msDS-PSOApplied" },
			{ "1.2.840.113556.1.4.2022","msDS-ResultantPSO" },
			{ "1.2.840.113556.1.4.2023","msDS-PasswordSettingsPrecedence" },
			{ "1.2.840.113556.1.4.2024","msDS-NcType" },
			{ "1.2.840.113556.1.4.2025","msDS-IsUserCachableAtRodc" },
			{ "1.2.840.113556.1.4.2030","msDFS-SchemaMajorVersion" },
			{ "1.2.840.113556.1.4.2031","msDFS-SchemaMinorVersion" },
			{ "1.2.840.113556.1.4.2032","msDFS-GenerationGUIDv2" },
			{ "1.2.840.113556.1.4.2033","msDFS-NamespaceIdentityGUIDv2" },
			{ "1.2.840.113556.1.4.2034","msDFS-LastModifiedv2" },
			{ "1.2.840.113556.1.4.2035","msDFS-Ttlv2" },
			{ "1.2.840.113556.1.4.2036","msDFS-Commentv2" },
			{ "1.2.840.113556.1.4.2037","msDFS-Propertiesv2" },
			{ "1.2.840.113556.1.4.2038","msDFS-TargetListv2" },
			{ "1.2.840.113556.1.4.2039","msDFS-LinkPathv2" },
			{ "1.2.840.113556.1.4.2040","msDFS-LinkSecurityDescriptorv2" },
			{ "1.2.840.113556.1.4.2041","msDFS-LinkIdentityGUIDv2" },
			{ "1.2.840.113556.1.4.2042","msDFS-ShortNameLinkPathv2" },
			{ "1.2.840.113556.1.4.2046","addressBookRoots2" },
			{ "1.2.840.113556.1.4.2047","globalAddressList2" },
			{ "1.2.840.113556.1.4.2048","templateRoots2" },
			{ "1.2.840.113556.1.4.2049","msDS-BridgeHeadServersUsed" },
			{ "1.2.840.113556.1.4.205","pKTGuid" },
			{ "1.2.840.113556.1.4.2050","msPKI-CredentialRoamingTokens" },
			{ "1.2.840.113556.1.4.2051","msDS-OIDToGroupLink" },
			{ "1.2.840.113556.1.4.2052","msDS-OIDToGroupLinkBl" },
			{ "1.2.840.113556.1.4.2053","msImaging-PSPIdentifier" },
			{ "1.2.840.113556.1.4.2054","msImaging-PSPString" },
			{ "1.2.840.113556.1.4.2055","msDS-USNLastSyncSuccess" },
			{ "1.2.840.113556.1.4.2056","msDS-HostServiceAccount" },
			{ "1.2.840.113556.1.4.2057","msDS-HostServiceAccountBL" },
			{ "1.2.840.113556.1.4.2058","isRecycled" },
			{ "1.2.840.113556.1.4.2059","msDS-LocalEffectiveDeletionTime" },
			{ "1.2.840.113556.1.4.206","pKT" },
			{ "1.2.840.113556.1.4.2060","msDS-LocalEffectiveRecycleTime" },
			{ "1.2.840.113556.1.4.2061","msDS-EnabledFeature" },
			{ "1.2.840.113556.1.4.2062","msDS-OptionalFeatureGUID" },
			{ "1.2.840.113556.1.4.2063","msDS-OptionalFeatureFlags" },
			{ "1.2.840.113556.1.4.2066","msDS-RequiredDomainBehaviorVersion" },
			{ "1.2.840.113556.1.4.2067","msDS-LastKnownRDN" },
			{ "1.2.840.113556.1.4.2068","msDS-DeletedObjectLifetime" },
			{ "1.2.840.113556.1.4.2069","msDS-EnabledFeatureBL" },
			{ "1.2.840.113556.1.4.2070","msTSEndpointData" },
			{ "1.2.840.113556.1.4.2071","msTSEndpointType" },
			{ "1.2.840.113556.1.4.2072","msTSEndpointPlugin" },
			{ "1.2.840.113556.1.4.2073","msTSPrimaryDesktop" },
			{ "1.2.840.113556.1.4.2074","msTSPrimaryDesktopBL" },
			{ "1.2.840.113556.1.4.2075","msTSSecondaryDesktops" },
			{ "1.2.840.113556.1.4.2076","msPKI-Enrollment-Servers" },
			{ "1.2.840.113556.1.4.2077","msPKI-Site-Name" },
			{ "1.2.840.113556.1.4.2078","msTSSecondaryDesktopBL" },
			{ "1.2.840.113556.1.4.2079","msDS-RequiredForestBehaviorVersion" },
			{ "1.2.840.113556.1.4.2081","msSPP-CSVLKSkuId" },
			{ "1.2.840.113556.1.4.2082","msSPP-KMSIds" },
			{ "1.2.840.113556.1.4.2083","msSPP-InstallationId" },
			{ "1.2.840.113556.1.4.2084","msSPP-ConfirmationId" },
			{ "1.2.840.113556.1.4.2085","msSPP-OnlineLicense" },
			{ "1.2.840.113556.1.4.2086","msSPP-PhoneLicense" },
			{ "1.2.840.113556.1.4.2087","msSPP-ConfigLicense" },
			{ "1.2.840.113556.1.4.2088","msSPP-IssuanceLicense" },
			{ "1.2.840.113556.1.4.2095","msDS-IsUsedAsResourceSecurityAttribute" },
			{ "1.2.840.113556.1.4.2097","msDS-ClaimPossibleValues" },
			{ "1.2.840.113556.1.4.2098","msDS-ClaimValueType" },
			{ "1.2.840.113556.1.4.2099","msDS-ClaimAttributeSource" },
			{ "1.2.840.113556.1.4.21","cOMProgID" },
			{ "1.2.840.113556.1.4.2100","msDS-ClaimTypeAppliesToClass" },
			{ "1.2.840.113556.1.4.2101","msDS-ClaimSharesPossibleValuesWith" },
			{ "1.2.840.113556.1.4.2102","msDS-ClaimSharesPossibleValuesWithBL" },
			{ "1.2.840.113556.1.4.2103","msDS-MembersOfResourcePropertyList" },
			{ "1.2.840.113556.1.4.2104","msDS-MembersOfResourcePropertyListBL" },
			{ "1.2.840.113556.1.4.2105","msSPP-CSVLKPid" },
			{ "1.2.840.113556.1.4.2106","msSPP-CSVLKPartialProductKey" },
			{ "1.2.840.113556.1.4.2107","msTPM-SrkPubThumbprint" },
			{ "1.2.840.113556.1.4.2108","msTPM-OwnerInformationTemp" },
			{ "1.2.840.113556.1.4.2109","msTPM-TpmInformationForComputer" },
			{ "1.2.840.113556.1.4.211","schedule" },
			{ "1.2.840.113556.1.4.2110","msTPM-TpmInformationForComputerBL" },
			{ "1.2.840.113556.1.4.2128","msDNS-KeymasterZones" },
			{ "1.2.840.113556.1.4.213","defaultClassStore" },
			{ "1.2.840.113556.1.4.2130","msDNS-IsSigned" },
			{ "1.2.840.113556.1.4.2131","msDNS-SignWithNSEC3" },
			{ "1.2.840.113556.1.4.2132","msDNS-NSEC3OptOut" },
			{ "1.2.840.113556.1.4.2133","msDNS-MaintainTrustAnchor" },
			{ "1.2.840.113556.1.4.2134","msDNS-DSRecordAlgorithms" },
			{ "1.2.840.113556.1.4.2135","msDNS-RFC5011KeyRollovers" },
			{ "1.2.840.113556.1.4.2136","msDNS-NSEC3HashAlgorithm" },
			{ "1.2.840.113556.1.4.2137","msDNS-NSEC3RandomSaltLength" },
			{ "1.2.840.113556.1.4.2138","msDNS-NSEC3Iterations" },
			{ "1.2.840.113556.1.4.2139","msDNS-DNSKEYRecordSetTTL" },
			{ "1.2.840.113556.1.4.214","nextLevelStore" },
			{ "1.2.840.113556.1.4.2140","msDNS-DSRecordSetTTL" },
			{ "1.2.840.113556.1.4.2141","msDNS-SignatureInceptionOffset" },
			{ "1.2.840.113556.1.4.2142","msDNS-SecureDelegationPollingPeriod" },
			{ "1.2.840.113556.1.4.2143","msDNS-SigningKeyDescriptors" },
			{ "1.2.840.113556.1.4.2144","msDNS-SigningKeys" },
			{ "1.2.840.113556.1.4.2145","msDNS-DNSKEYRecords" },
			{ "1.2.840.113556.1.4.2146","msDNS-ParentHasSecureDelegation" },
			{ "1.2.840.113556.1.4.2147","msDNS-PropagationTime" },
			{ "1.2.840.113556.1.4.2148","msDNS-NSEC3UserSalt" },
			{ "1.2.840.113556.1.4.2149","msDNS-NSEC3CurrentSalt" },
			{ "1.2.840.113556.1.4.2150","msAuthz-EffectiveSecurityPolicy" },
			{ "1.2.840.113556.1.4.2151","msAuthz-ProposedSecurityPolicy" },
			{ "1.2.840.113556.1.4.2152","msAuthz-LastEffectiveSecurityPolicy" },
			{ "1.2.840.113556.1.4.2153","msAuthz-ResourceCondition" },
			{ "1.2.840.113556.1.4.2154","msAuthz-CentralAccessPolicyID" },
			{ "1.2.840.113556.1.4.2155","msAuthz-MemberRulesInCentralAccessPolicy" },
			{ "1.2.840.113556.1.4.2156","msAuthz-MemberRulesInCentralAccessPolicyBL" },
			{ "1.2.840.113556.1.4.2157","msDS-ClaimSource" },
			{ "1.2.840.113556.1.4.2158","msDS-ClaimSourceType" },
			{ "1.2.840.113556.1.4.2159","msDS-ClaimIsValueSpaceRestricted" },
			{ "1.2.840.113556.1.4.2160","msDS-ClaimIsSingleValued" },
			{ "1.2.840.113556.1.4.2166","msDS-GenerationId" },
			{ "1.2.840.113556.1.4.2167","msDS-PrimaryComputer" },
			{ "1.2.840.113556.1.4.2168","msDS-IsPrimaryComputerFor" },
			{ "1.2.840.113556.1.4.2169","msKds-KDFAlgorithmID" },
			{ "1.2.840.113556.1.4.2170","msKds-KDFParam" },
			{ "1.2.840.113556.1.4.2171","msKds-SecretAgreementAlgorithmID" },
			{ "1.2.840.113556.1.4.2172","msKds-SecretAgreementParam" },
			{ "1.2.840.113556.1.4.2173","msKds-PublicKeyLength" },
			{ "1.2.840.113556.1.4.2174","msKds-PrivateKeyLength" },
			{ "1.2.840.113556.1.4.2175","msKds-RootKeyData" },
			{ "1.2.840.113556.1.4.2176","msKds-Version" },
			{ "1.2.840.113556.1.4.2177","msKds-DomainID" },
			{ "1.2.840.113556.1.4.2178","msKds-UseStartTime" },
			{ "1.2.840.113556.1.4.2179","msKds-CreateTime" },
			{ "1.2.840.113556.1.4.218","applicationName" },
			{ "1.2.840.113556.1.4.2180","msImaging-ThumbprintHash" },
			{ "1.2.840.113556.1.4.2181","msImaging-HashAlgorithm" },
			{ "1.2.840.113556.1.4.2182","msDS-AllowedToActOnBehalfOfOtherIdentity" },
			{ "1.2.840.113556.1.4.2183","msDS-GeoCoordinatesAltitude" },
			{ "1.2.840.113556.1.4.2184","msDS-GeoCoordinatesLatitude" },
			{ "1.2.840.113556.1.4.2185","msDS-GeoCoordinatesLongitude" },
			{ "1.2.840.113556.1.4.2186","msDS-IsPossibleValuesPresent" },
			{ "1.2.840.113556.1.4.2187","msDS-ValueTypeReference" },
			{ "1.2.840.113556.1.4.2188","msDS-ValueTypeReferenceBL" },
			{ "1.2.840.113556.1.4.2189","msDS-TransformationRules" },
			{ "1.2.840.113556.1.4.219","iconPath" },
			{ "1.2.840.113556.1.4.2190","msDS-TransformationRulesCompiled" },
			{ "1.2.840.113556.1.4.2191","msDS-IngressClaimsTransformationPolicy" },
			{ "1.2.840.113556.1.4.2192","msDS-EgressClaimsTransformationPolicy" },
			{ "1.2.840.113556.1.4.2193","msDS-TDOIngressBL" },
			{ "1.2.840.113556.1.4.2194","msDS-TDOEgressBL" },
			{ "1.2.840.113556.1.4.2195","msDS-AppliesToResourceTypes" },
			{ "1.2.840.113556.1.4.2196","msDS-ManagedPassword" },
			{ "1.2.840.113556.1.4.2197","msDS-ManagedPasswordId" },
			{ "1.2.840.113556.1.4.2198","msDS-ManagedPasswordPreviousId" },
			{ "1.2.840.113556.1.4.2199","msDS-ManagedPasswordInterval" },
			{ "1.2.840.113556.1.4.2200","msDS-GroupMSAMembership" },
			{ "1.2.840.113556.1.4.221","sAMAccountName" },
			{ "1.2.840.113556.1.4.222","location" },
			{ "1.2.840.113556.1.4.223","serverName" },
			{ "1.2.840.113556.1.4.224","defaultSecurityDescriptor" },
			{ "1.2.840.113556.1.4.228","portName" },
			{ "1.2.840.113556.1.4.229","driverName" },
			{ "1.2.840.113556.1.4.230","printSeparatorFile" },
			{ "1.2.840.113556.1.4.231","priority" },
			{ "1.2.840.113556.1.4.232","defaultPriority" },
			{ "1.2.840.113556.1.4.233","printStartTime" },
			{ "1.2.840.113556.1.4.234","printEndTime" },
			{ "1.2.840.113556.1.4.235","printFormName" },
			{ "1.2.840.113556.1.4.237","printBinNames" },
			{ "1.2.840.113556.1.4.238","printMaxResolutionSupported" },
			{ "1.2.840.113556.1.4.24","contentIndexingAllowed" },
			{ "1.2.840.113556.1.4.240","printOrientationsSupported" },
			{ "1.2.840.113556.1.4.241","printMaxCopies" },
			{ "1.2.840.113556.1.4.242","printCollate" },
			{ "1.2.840.113556.1.4.243","printColor" },
			{ "1.2.840.113556.1.4.246","printLanguage" },
			{ "1.2.840.113556.1.4.247","printAttributes" },
			{ "1.2.840.113556.1.4.249","cOMCLSID" },
			{ "1.2.840.113556.1.4.25","countryCode" },
			{ "1.2.840.113556.1.4.250","cOMUniqueLIBID" },
			{ "1.2.840.113556.1.4.251","cOMTreatAsClassId" },
			{ "1.2.840.113556.1.4.253","cOMOtherProgId" },
			{ "1.2.840.113556.1.4.254","cOMTypelibId" },
			{ "1.2.840.113556.1.4.255","vendor" },
			{ "1.2.840.113556.1.4.26","creationTime" },
			{ "1.2.840.113556.1.4.261","division" },
			{ "1.2.840.113556.1.4.265","notes" },
			{ "1.2.840.113556.1.4.268","eFSPolicy" },
			{ "1.2.840.113556.1.4.269","linkTrackSecret" },
			{ "1.2.840.113556.1.4.27","currentValue" },
			{ "1.2.840.113556.1.4.270","printShareName" },
			{ "1.2.840.113556.1.4.271","printOwner" },
			{ "1.2.840.113556.1.4.272","printNotify" },
			{ "1.2.840.113556.1.4.273","printStatus" },
			{ "1.2.840.113556.1.4.274","printSpooling" },
			{ "1.2.840.113556.1.4.275","printKeepPrintedJobs" },
			{ "1.2.840.113556.1.4.276","driverVersion" },
			{ "1.2.840.113556.1.4.277","printMaxXExtent" },
			{ "1.2.840.113556.1.4.278","printMaxYExtent" },
			{ "1.2.840.113556.1.4.279","printMinXExtent" },
			{ "1.2.840.113556.1.4.28","dnsRoot" },
			{ "1.2.840.113556.1.4.280","printMinYExtent" },
			{ "1.2.840.113556.1.4.281","printStaplingSupported" },
			{ "1.2.840.113556.1.4.282","printMemory" },
			{ "1.2.840.113556.1.4.283","assetNumber" },
			{ "1.2.840.113556.1.4.284","bytesPerMinute" },
			{ "1.2.840.113556.1.4.285","printRate" },
			{ "1.2.840.113556.1.4.286","printRateUnit" },
			{ "1.2.840.113556.1.4.287","printNetworkAddress" },
			{ "1.2.840.113556.1.4.288","printMACAddress" },
			{ "1.2.840.113556.1.4.289","printMediaReady" },
			{ "1.2.840.113556.1.4.290","printNumberUp" },
			{ "1.2.840.113556.1.4.299","printMediaSupported" },
			{ "1.2.840.113556.1.4.3","replPropertyMetaData" },
			{ "1.2.840.113556.1.4.300","printerName" },
			{ "1.2.840.113556.1.4.301","wbemPath" },
			{ "1.2.840.113556.1.4.302","sAMAccountType" },
			{ "1.2.840.113556.1.4.303","notificationList" },
			{ "1.2.840.113556.1.4.307","options" },
			{ "1.2.840.113556.1.4.31","fRSReplicaSetType" },
			{ "1.2.840.113556.1.4.312","rpcNsObjectID" },
			{ "1.2.840.113556.1.4.314","rpcNsTransferSyntax" },
			{ "1.2.840.113556.1.4.32","domainPolicyObject" },
			{ "1.2.840.113556.1.4.320","implementedCategories" },
			{ "1.2.840.113556.1.4.321","requiredCategories" },
			{ "1.2.840.113556.1.4.322","categoryId" },
			{ "1.2.840.113556.1.4.324","packageType" },
			{ "1.2.840.113556.1.4.325","setupCommand" },
			{ "1.2.840.113556.1.4.326","packageName" },
			{ "1.2.840.113556.1.4.327","packageFlags" },
			{ "1.2.840.113556.1.4.328","versionNumberHi" },
			{ "1.2.840.113556.1.4.329","versionNumberLo" },
			{ "1.2.840.113556.1.4.330","lastUpdateSequence" },
			{ "1.2.840.113556.1.4.332","birthLocation" },
			{ "1.2.840.113556.1.4.333","oMTIndxGuid" },
			{ "1.2.840.113556.1.4.334","volTableIdxGUID" },
			{ "1.2.840.113556.1.4.335","currentLocation" },
			{ "1.2.840.113556.1.4.336","volTableGUID" },
			{ "1.2.840.113556.1.4.337","currMachineId" },
			{ "1.2.840.113556.1.4.340","rightsGuid" },
			{ "1.2.840.113556.1.4.341","appliesTo" },
			{ "1.2.840.113556.1.4.344","groupsToIgnore" },
			{ "1.2.840.113556.1.4.345","groupPriority" },
			{ "1.2.840.113556.1.4.346","desktopProfile" },
			{ "1.2.840.113556.1.4.35","employeeID" },
			{ "1.2.840.113556.1.4.356","foreignIdentifier" },
			{ "1.2.840.113556.1.4.357","nTMixedDomain" },
			{ "1.2.840.113556.1.4.358","netbootInitialization" },
			{ "1.2.840.113556.1.4.359","netbootGUID" },
			{ "1.2.840.113556.1.4.36","enabledConnection" },
			{ "1.2.840.113556.1.4.361","netbootMachineFilePath" },
			{ "1.2.840.113556.1.4.362","siteGUID" },
			{ "1.2.840.113556.1.4.363","operatingSystem" },
			{ "1.2.840.113556.1.4.364","operatingSystemVersion" },
			{ "1.2.840.113556.1.4.365","operatingSystemServicePack" },
			{ "1.2.840.113556.1.4.366","rpcNsAnnotation" },
			{ "1.2.840.113556.1.4.367","rpcNsCodeset" },
			{ "1.2.840.113556.1.4.368","rIDManagerReference" },
			{ "1.2.840.113556.1.4.369","fSMORoleOwner" },
			{ "1.2.840.113556.1.4.370","rIDAvailablePool" },
			{ "1.2.840.113556.1.4.371","rIDAllocationPool" },
			{ "1.2.840.113556.1.4.372","rIDPreviousAllocationPool" },
			{ "1.2.840.113556.1.4.373","rIDUsedPool" },
			{ "1.2.840.113556.1.4.374","rIDNextRID" },
			{ "1.2.840.113556.1.4.375","systemFlags" },
			{ "1.2.840.113556.1.4.378","dnsAllowDynamic" },
			{ "1.2.840.113556.1.4.379","dnsAllowXFR" },
			{ "1.2.840.113556.1.4.38","flags" },
			{ "1.2.840.113556.1.4.380","dnsSecureSecondaries" },
			{ "1.2.840.113556.1.4.381","dnsNotifySecondaries" },
			{ "1.2.840.113556.1.4.382","dnsRecord" },
			{ "1.2.840.113556.1.4.39","forceLogoff" },
			{ "1.2.840.113556.1.4.4","replUpToDateVector" },
			{ "1.2.840.113556.1.4.40","fromServer" },
			{ "1.2.840.113556.1.4.41","generatedConnection" },
			{ "1.2.840.113556.1.4.415","operatingSystemHotfix" },
			{ "1.2.840.113556.1.4.420","publicKeyPolicy" },
			{ "1.2.840.113556.1.4.421","domainWidePolicy" },
			{ "1.2.840.113556.1.4.422","domainPolicyReference" },
			{ "1.2.840.113556.1.4.43","fRSVersionGUID" },
			{ "1.2.840.113556.1.4.44","homeDirectory" },
			{ "1.2.840.113556.1.4.45","homeDrive" },
			{ "1.2.840.113556.1.4.457","localPolicyReference" },
			{ "1.2.840.113556.1.4.458","qualityOfService" },
			{ "1.2.840.113556.1.4.459","machineWidePolicy" },
			{ "1.2.840.113556.1.4.470","trustAttributes" },
			{ "1.2.840.113556.1.4.471","trustParent" },
			{ "1.2.840.113556.1.4.472","domainCrossRef" },
			{ "1.2.840.113556.1.4.48","keywords" },
			{ "1.2.840.113556.1.4.480","defaultGroup" },
			{ "1.2.840.113556.1.4.481","schemaUpdate" },
			{ "1.2.840.113556.1.4.483","fRSFileFilter" },
			{ "1.2.840.113556.1.4.484","fRSDirectoryFilter" },
			{ "1.2.840.113556.1.4.485","fRSUpdateTimeout" },
			{ "1.2.840.113556.1.4.486","fRSWorkingPath" },
			{ "1.2.840.113556.1.4.487","fRSRootPath" },
			{ "1.2.840.113556.1.4.488","fRSStagingPath" },
			{ "1.2.840.113556.1.4.49","badPasswordTime" },
			{ "1.2.840.113556.1.4.490","fRSDSPoll" },
			{ "1.2.840.113556.1.4.491","fRSFaultCondition" },
			{ "1.2.840.113556.1.4.494","siteServer" },
			{ "1.2.840.113556.1.4.498","creationWizard" },
			{ "1.2.840.113556.1.4.499","contextMenu" },
			{ "1.2.840.113556.1.4.50","lastContentIndexed" },
			{ "1.2.840.113556.1.4.500","fRSServiceCommand" },
			{ "1.2.840.113556.1.4.502","timeVolChange" },
			{ "1.2.840.113556.1.4.503","timeRefresh" },
			{ "1.2.840.113556.1.4.504","seqNotification" },
			{ "1.2.840.113556.1.4.505","oMTGuid" },
			{ "1.2.840.113556.1.4.506","objectCount" },
			{ "1.2.840.113556.1.4.507","volumeCount" },
			{ "1.2.840.113556.1.4.509","serviceClassName" },
			{ "1.2.840.113556.1.4.51","lastLogoff" },
			{ "1.2.840.113556.1.4.510","serviceBindingInformation" },
			{ "1.2.840.113556.1.4.511","flatName" },
			{ "1.2.840.113556.1.4.512","siteObject" },
			{ "1.2.840.113556.1.4.513","siteObjectBL" },
			{ "1.2.840.113556.1.4.514","physicalLocationObject" },
			{ "1.2.840.113556.1.4.515","serverReference" },
			{ "1.2.840.113556.1.4.516","serverReferenceBL" },
			{ "1.2.840.113556.1.4.517","ipsecPolicyReference" },
			{ "1.2.840.113556.1.4.518","defaultHidingValue" },
			{ "1.2.840.113556.1.4.519","lastBackupRestorationTime" },
			{ "1.2.840.113556.1.4.52","lastLogon" },
			{ "1.2.840.113556.1.4.520","machinePasswordChangeInterval" },
			{ "1.2.840.113556.1.4.53","lastSetTime" },
			{ "1.2.840.113556.1.4.530","nonSecurityMember" },
			{ "1.2.840.113556.1.4.531","nonSecurityMemberBL" },
			{ "1.2.840.113556.1.4.532","superiorDNSRoot" },
			{ "1.2.840.113556.1.4.533","fRSReplicaSetGUID" },
			{ "1.2.840.113556.1.4.534","fRSLevelLimit" },
			{ "1.2.840.113556.1.4.535","fRSRootSecurity" },
			{ "1.2.840.113556.1.4.536","fRSExtensions" },
			{ "1.2.840.113556.1.4.537","dynamicLDAPServer" },
			{ "1.2.840.113556.1.4.538","prefixMap" },
			{ "1.2.840.113556.1.4.539","initialAuthIncoming" },
			{ "1.2.840.113556.1.4.540","initialAuthOutgoing" },
			{ "1.2.840.113556.1.4.55","dBCSPwd" },
			{ "1.2.840.113556.1.4.557","parentCA" },
			{ "1.2.840.113556.1.4.56","localPolicyFlags" },
			{ "1.2.840.113556.1.4.562","adminPropertyPages" },
			{ "1.2.840.113556.1.4.563","shellPropertyPages" },
			{ "1.2.840.113556.1.4.565","meetingID" },
			{ "1.2.840.113556.1.4.566","meetingName" },
			{ "1.2.840.113556.1.4.567","meetingDescription" },
			{ "1.2.840.113556.1.4.568","meetingKeyword" },
			{ "1.2.840.113556.1.4.569","meetingLocation" },
			{ "1.2.840.113556.1.4.57","defaultLocalPolicyObject" },
			{ "1.2.840.113556.1.4.570","meetingProtocol" },
			{ "1.2.840.113556.1.4.571","meetingType" },
			{ "1.2.840.113556.1.4.573","meetingApplication" },
			{ "1.2.840.113556.1.4.574","meetingLanguage" },
			{ "1.2.840.113556.1.4.576","meetingMaxParticipants" },
			{ "1.2.840.113556.1.4.577","meetingOriginator" },
			{ "1.2.840.113556.1.4.578","meetingContactInfo" },
			{ "1.2.840.113556.1.4.579","meetingOwner" },
			{ "1.2.840.113556.1.4.58","localeID" },
			{ "1.2.840.113556.1.4.580","meetingIP" },
			{ "1.2.840.113556.1.4.581","meetingScope" },
			{ "1.2.840.113556.1.4.582","meetingAdvertiseScope" },
			{ "1.2.840.113556.1.4.583","meetingURL" },
			{ "1.2.840.113556.1.4.584","meetingRating" },
			{ "1.2.840.113556.1.4.585","meetingIsEncrypted" },
			{ "1.2.840.113556.1.4.586","meetingRecurrence" },
			{ "1.2.840.113556.1.4.587","meetingStartTime" },
			{ "1.2.840.113556.1.4.588","meetingEndTime" },
			{ "1.2.840.113556.1.4.589","meetingBandwidth" },
			{ "1.2.840.113556.1.4.590","meetingBlob" },
			{ "1.2.840.113556.1.4.60","lockoutDuration" },
			{ "1.2.840.113556.1.4.607","queryPolicyObject" },
			{ "1.2.840.113556.1.4.608","queryPolicyBL" },
			{ "1.2.840.113556.1.4.609","sIDHistory" },
			{ "1.2.840.113556.1.4.61","lockOutObservationWindow" },
			{ "1.2.840.113556.1.4.610","classDisplayName" },
			{ "1.2.840.113556.1.4.614","adminContextMenu" },
			{ "1.2.840.113556.1.4.615","shellContextMenu" },
			{ "1.2.840.113556.1.4.618","wellKnownObjects" },
			{ "1.2.840.113556.1.4.619","dNSHostName" },
			{ "1.2.840.113556.1.4.62","scriptPath" },
			{ "1.2.840.113556.1.4.620","ipsecName" },
			{ "1.2.840.113556.1.4.621","ipsecID" },
			{ "1.2.840.113556.1.4.622","ipsecDataType" },
			{ "1.2.840.113556.1.4.623","ipsecData" },
			{ "1.2.840.113556.1.4.624","ipsecOwnersReference" },
			{ "1.2.840.113556.1.4.626","ipsecISAKMPReference" },
			{ "1.2.840.113556.1.4.627","ipsecNFAReference" },
			{ "1.2.840.113556.1.4.628","ipsecNegotiationPolicyReference" },
			{ "1.2.840.113556.1.4.629","ipsecFilterReference" },
			{ "1.2.840.113556.1.4.631","printPagesPerMinute" },
			{ "1.2.840.113556.1.4.633","policyReplicationFlags" },
			{ "1.2.840.113556.1.4.634","privilegeDisplayName" },
			{ "1.2.840.113556.1.4.635","privilegeValue" },
			{ "1.2.840.113556.1.4.636","privilegeAttributes" },
			{ "1.2.840.113556.1.4.637","privilegeHolder" },
			{ "1.2.840.113556.1.4.638","isPrivilegeHolder" },
			{ "1.2.840.113556.1.4.639","isMemberOfPartialAttributeSet" },
			{ "1.2.840.113556.1.4.64","logonHours" },
			{ "1.2.840.113556.1.4.640","partialAttributeSet" },
			{ "1.2.840.113556.1.4.644","showInAddressBook" },
			{ "1.2.840.113556.1.4.645","userCert" },
			{ "1.2.840.113556.1.4.646","otherFacsimileTelephoneNumber" },
			{ "1.2.840.113556.1.4.647","otherMobile" },
			{ "1.2.840.113556.1.4.648","primaryTelexNumber" },
			{ "1.2.840.113556.1.4.649","primaryInternationalISDNNumber" },
			{ "1.2.840.113556.1.4.65","logonWorkstation" },
			{ "1.2.840.113556.1.4.650","mhsORAddress" },
			{ "1.2.840.113556.1.4.651","otherMailbox" },
			{ "1.2.840.113556.1.4.652","assistant" },
			{ "1.2.840.113556.1.4.653","managedBy" },
			{ "1.2.840.113556.1.4.654","managedObjects" },
			{ "1.2.840.113556.1.4.655","legacyExchangeDN" },
			{ "1.2.840.113556.1.4.656","userPrincipalName" },
			{ "1.2.840.113556.1.4.657","serviceDNSName" },
			{ "1.2.840.113556.1.4.659","serviceDNSNameType" },
			{ "1.2.840.113556.1.4.66","lSACreationTime" },
			{ "1.2.840.113556.1.4.660","treeName" },
			{ "1.2.840.113556.1.4.661","isDefunct" },
			{ "1.2.840.113556.1.4.662","lockoutTime" },
			{ "1.2.840.113556.1.4.663","partialAttributeDeletionList" },
			{ "1.2.840.113556.1.4.664","syncWithObject" },
			{ "1.2.840.113556.1.4.665","syncMembership" },
			{ "1.2.840.113556.1.4.666","syncAttributes" },
			{ "1.2.840.113556.1.4.667","syncWithSID" },
			{ "1.2.840.113556.1.4.668","domainCAs" },
			{ "1.2.840.113556.1.4.669","rIDSetReferences" },
			{ "1.2.840.113556.1.4.67","lSAModifiedCount" },
			{ "1.2.840.113556.1.4.671","msiFileList" },
			{ "1.2.840.113556.1.4.672","categories" },
			{ "1.2.840.113556.1.4.673","retiredReplDSASignatures" },
			{ "1.2.840.113556.1.4.674","rootTrust" },
			{ "1.2.840.113556.1.4.675","catalogs" },
			{ "1.2.840.113556.1.4.677","replTopologyStayOfExecution" },
			{ "1.2.840.113556.1.4.679","creator" },
			{ "1.2.840.113556.1.4.68","machineArchitecture" },
			{ "1.2.840.113556.1.4.680","queryPoint" },
			{ "1.2.840.113556.1.4.681","indexedScopes" },
			{ "1.2.840.113556.1.4.682","friendlyNames" },
			{ "1.2.840.113556.1.4.683","cRLPartitionedRevocationList" },
			{ "1.2.840.113556.1.4.684","certificateAuthorityObject" },
			{ "1.2.840.113556.1.4.685","parentCACertificateChain" },
			{ "1.2.840.113556.1.4.686","domainID" },
			{ "1.2.840.113556.1.4.687","cAConnect" },
			{ "1.2.840.113556.1.4.688","cAWEBURL" },
			{ "1.2.840.113556.1.4.689","cRLObject" },
			{ "1.2.840.113556.1.4.690","cAUsages" },
			{ "1.2.840.113556.1.4.692","previousCACertificates" },
			{ "1.2.840.113556.1.4.693","pendingCACertificates" },
			{ "1.2.840.113556.1.4.694","previousParentCA" },
			{ "1.2.840.113556.1.4.695","pendingParentCA" },
			{ "1.2.840.113556.1.4.696","currentParentCA" },
			{ "1.2.840.113556.1.4.697","cACertificateDN" },
			{ "1.2.840.113556.1.4.698","dhcpUniqueKey" },
			{ "1.2.840.113556.1.4.699","dhcpType" },
			{ "1.2.840.113556.1.4.700","dhcpFlags" },
			{ "1.2.840.113556.1.4.701","dhcpIdentification" },
			{ "1.2.840.113556.1.4.702","dhcpObjName" },
			{ "1.2.840.113556.1.4.703","dhcpObjDescription" },
			{ "1.2.840.113556.1.4.704","dhcpServers" },
			{ "1.2.840.113556.1.4.705","dhcpSubnets" },
			{ "1.2.840.113556.1.4.706","dhcpMask" },
			{ "1.2.840.113556.1.4.707","dhcpRanges" },
			{ "1.2.840.113556.1.4.708","dhcpSites" },
			{ "1.2.840.113556.1.4.709","dhcpReservations" },
			{ "1.2.840.113556.1.4.71","machineRole" },
			{ "1.2.840.113556.1.4.710","superScopes" },
			{ "1.2.840.113556.1.4.711","superScopeDescription" },
			{ "1.2.840.113556.1.4.712","optionDescription" },
			{ "1.2.840.113556.1.4.713","optionsLocation" },
			{ "1.2.840.113556.1.4.714","dhcpOptions" },
			{ "1.2.840.113556.1.4.715","dhcpClasses" },
			{ "1.2.840.113556.1.4.716","mscopeId" },
			{ "1.2.840.113556.1.4.717","dhcpState" },
			{ "1.2.840.113556.1.4.718","dhcpProperties" },
			{ "1.2.840.113556.1.4.719","dhcpMaxKey" },
			{ "1.2.840.113556.1.4.72","marshalledInterface" },
			{ "1.2.840.113556.1.4.720","dhcpUpdateTime" },
			{ "1.2.840.113556.1.4.721","ipPhone" },
			{ "1.2.840.113556.1.4.722","otherIpPhone" },
			{ "1.2.840.113556.1.4.73","lockoutThreshold" },
			{ "1.2.840.113556.1.4.74","maxPwdAge" },
			{ "1.2.840.113556.1.4.748","attributeDisplayNames" },
			{ "1.2.840.113556.1.4.749","url" },
			{ "1.2.840.113556.1.4.75","maxRenewAge" },
			{ "1.2.840.113556.1.4.750","groupType" },
			{ "1.2.840.113556.1.4.751","userSharedFolder" },
			{ "1.2.840.113556.1.4.752","userSharedFolderOther" },
			{ "1.2.840.113556.1.4.753","nameServiceFlags" },
			{ "1.2.840.113556.1.4.754","rpcNsEntryFlags" },
			{ "1.2.840.113556.1.4.755","domainIdentifier" },
			{ "1.2.840.113556.1.4.756","aCSTimeOfDay" },
			{ "1.2.840.113556.1.4.757","aCSDirection" },
			{ "1.2.840.113556.1.4.758","aCSMaxTokenRatePerFlow" },
			{ "1.2.840.113556.1.4.759","aCSMaxPeakBandwidthPerFlow" },
			{ "1.2.840.113556.1.4.76","maxStorage" },
			{ "1.2.840.113556.1.4.760","aCSAggregateTokenRatePerUser" },
			{ "1.2.840.113556.1.4.761","aCSMaxDurationPerFlow" },
			{ "1.2.840.113556.1.4.762","aCSServiceType" },
			{ "1.2.840.113556.1.4.763","aCSTotalNoOfFlows" },
			{ "1.2.840.113556.1.4.764","aCSPriority" },
			{ "1.2.840.113556.1.4.765","aCSPermissionBits" },
			{ "1.2.840.113556.1.4.766","aCSAllocableRSVPBandwidth" },
			{ "1.2.840.113556.1.4.767","aCSMaxPeakBandwidth" },
			{ "1.2.840.113556.1.4.768","aCSEnableRSVPMessageLogging" },
			{ "1.2.840.113556.1.4.769","aCSEventLogLevel" },
			{ "1.2.840.113556.1.4.77","maxTicketAge" },
			{ "1.2.840.113556.1.4.770","aCSEnableACSService" },
			{ "1.2.840.113556.1.4.771","servicePrincipalName" },
			{ "1.2.840.113556.1.4.772","aCSPolicyName" },
			{ "1.2.840.113556.1.4.773","aCSRSVPLogFilesLocation" },
			{ "1.2.840.113556.1.4.774","aCSMaxNoOfLogFiles" },
			{ "1.2.840.113556.1.4.775","aCSMaxSizeOfRSVPLogFile" },
			{ "1.2.840.113556.1.4.776","aCSDSBMPriority" },
			{ "1.2.840.113556.1.4.777","aCSDSBMRefresh" },
			{ "1.2.840.113556.1.4.778","aCSDSBMDeadTime" },
			{ "1.2.840.113556.1.4.779","aCSCacheTimeout" },
			{ "1.2.840.113556.1.4.78","minPwdAge" },
			{ "1.2.840.113556.1.4.780","aCSNonReservedTxLimit" },
			{ "1.2.840.113556.1.4.781","lastKnownParent" },
			{ "1.2.840.113556.1.4.782","objectCategory" },
			{ "1.2.840.113556.1.4.783","defaultObjectCategory" },
			{ "1.2.840.113556.1.4.784","aCSIdentityName" },
			{ "1.2.840.113556.1.4.786","mailAddress" },
			{ "1.2.840.113556.1.4.789","transportDLLName" },
			{ "1.2.840.113556.1.4.79","minPwdLength" },
			{ "1.2.840.113556.1.4.791","transportType" },
			{ "1.2.840.113556.1.4.8","userAccountControl" },
			{ "1.2.840.113556.1.4.80","minTicketAge" },
			{ "1.2.840.113556.1.4.806","treatAsLeaf" },
			{ "1.2.840.113556.1.4.809","remoteStorageGUID" },
			{ "1.2.840.113556.1.4.81","modifiedCountAtLastProm" },
			{ "1.2.840.113556.1.4.810","createDialog" },
			{ "1.2.840.113556.1.4.812","createWizardExt" },
			{ "1.2.840.113556.1.4.813","upgradeProductCode" },
			{ "1.2.840.113556.1.4.814","msiScript" },
			{ "1.2.840.113556.1.4.815","canUpgradeScript" },
			{ "1.2.840.113556.1.4.816","fileExtPriority" },
			{ "1.2.840.113556.1.4.817","localizedDescription" },
			{ "1.2.840.113556.1.4.818","productCode" },
			{ "1.2.840.113556.1.4.819","bridgeheadTransportList" },
			{ "1.2.840.113556.1.4.82","moniker" },
			{ "1.2.840.113556.1.4.820","bridgeheadServerListBL" },
			{ "1.2.840.113556.1.4.821","siteList" },
			{ "1.2.840.113556.1.4.822","siteLinkList" },
			{ "1.2.840.113556.1.4.823","certificateTemplates" },
			{ "1.2.840.113556.1.4.824","signatureAlgorithms" },
			{ "1.2.840.113556.1.4.825","enrollmentProviders" },
			{ "1.2.840.113556.1.4.83","monikerDisplayName" },
			{ "1.2.840.113556.1.4.843","lDAPAdminLimits" },
			{ "1.2.840.113556.1.4.844","lDAPIPDenyList" },
			{ "1.2.840.113556.1.4.845","msiScriptName" },
			{ "1.2.840.113556.1.4.846","msiScriptSize" },
			{ "1.2.840.113556.1.4.847","installUiLevel" },
			{ "1.2.840.113556.1.4.848","appSchemaVersion" },
			{ "1.2.840.113556.1.4.849","netbootAllowNewClients" },
			{ "1.2.840.113556.1.4.850","netbootLimitClients" },
			{ "1.2.840.113556.1.4.851","netbootMaxClients" },
			{ "1.2.840.113556.1.4.852","netbootCurrentClientCount" },
			{ "1.2.840.113556.1.4.853","netbootAnswerRequests" },
			{ "1.2.840.113556.1.4.854","netbootAnswerOnlyValidClients" },
			{ "1.2.840.113556.1.4.855","netbootNewMachineNamingPolicy" },
			{ "1.2.840.113556.1.4.856","netbootNewMachineOU" },
			{ "1.2.840.113556.1.4.857","netbootIntelliMirrorOSes" },
			{ "1.2.840.113556.1.4.858","netbootTools" },
			{ "1.2.840.113556.1.4.859","netbootLocallyInstalledOSes" },
			{ "1.2.840.113556.1.4.86","userWorkstations" },
			{ "1.2.840.113556.1.4.860","netbootServer" },
			{ "1.2.840.113556.1.4.864","netbootSCPBL" },
			{ "1.2.840.113556.1.4.865","pekList" },
			{ "1.2.840.113556.1.4.866","pekKeyChangeInterval" },
			{ "1.2.840.113556.1.4.867","altSecurityIdentities" },
			{ "1.2.840.113556.1.4.868","isCriticalSystemObject" },
			{ "1.2.840.113556.1.4.869","frsComputerReference" },
			{ "1.2.840.113556.1.4.87","nETBIOSName" },
			{ "1.2.840.113556.1.4.870","frsComputerReferenceBL" },
			{ "1.2.840.113556.1.4.871","fRSControlDataCreation" },
			{ "1.2.840.113556.1.4.872","fRSControlInboundBacklog" },
			{ "1.2.840.113556.1.4.873","fRSControlOutboundBacklog" },
			{ "1.2.840.113556.1.4.874","fRSFlags" },
			{ "1.2.840.113556.1.4.875","fRSMemberReference" },
			{ "1.2.840.113556.1.4.876","fRSMemberReferenceBL" },
			{ "1.2.840.113556.1.4.877","fRSPartnerAuthLevel" },
			{ "1.2.840.113556.1.4.878","fRSPrimaryMember" },
			{ "1.2.840.113556.1.4.879","fRSServiceCommandStatus" },
			{ "1.2.840.113556.1.4.88","nextRid" },
			{ "1.2.840.113556.1.4.880","fRSTimeLastCommand" },
			{ "1.2.840.113556.1.4.881","fRSTimeLastConfigChange" },
			{ "1.2.840.113556.1.4.882","fRSVersion" },
			{ "1.2.840.113556.1.4.883","msRRASVendorAttributeEntry" },
			{ "1.2.840.113556.1.4.884","msRRASAttribute" },
			{ "1.2.840.113556.1.4.885","terminalServer" },
			{ "1.2.840.113556.1.4.886","purportedSearch" },
			{ "1.2.840.113556.1.4.887","iPSECNegotiationPolicyType" },
			{ "1.2.840.113556.1.4.888","iPSECNegotiationPolicyAction" },
			{ "1.2.840.113556.1.4.889","additionalTrustedServiceNames" },
			{ "1.2.840.113556.1.4.89","nTGroupMembers" },
			{ "1.2.840.113556.1.4.890","uPNSuffixes" },
			{ "1.2.840.113556.1.4.891","gPLink" },
			{ "1.2.840.113556.1.4.892","gPOptions" },
			{ "1.2.840.113556.1.4.893","gPCFunctionalityVersion" },
			{ "1.2.840.113556.1.4.894","gPCFileSysPath" },
			{ "1.2.840.113556.1.4.895","transportAddressAttribute" },
			{ "1.2.840.113556.1.4.896","uSNSource" },
			{ "1.2.840.113556.1.4.897","aCSMaxAggregatePeakRatePerUser" },
			{ "1.2.840.113556.1.4.898","aCSNonReservedTxSize" },
			{ "1.2.840.113556.1.4.899","aCSEnableRSVPAccounting" },
			{ "1.2.840.113556.1.4.90","unicodePwd" },
			{ "1.2.840.113556.1.4.900","aCSRSVPAccountFilesLocation" },
			{ "1.2.840.113556.1.4.901","aCSMaxNoOfAccountFiles" },
			{ "1.2.840.113556.1.4.902","aCSMaxSizeOfRSVPAccountFile" },
			{ "1.2.840.113556.1.4.908","extendedClassInfo" },
			{ "1.2.840.113556.1.4.909","extendedAttributeInfo" },
			{ "1.2.840.113556.1.4.91","otherLoginWorkstations" },
			{ "1.2.840.113556.1.4.910","fromEntry" },
			{ "1.2.840.113556.1.4.911","allowedChildClasses" },
			{ "1.2.840.113556.1.4.912","allowedChildClassesEffective" },
			{ "1.2.840.113556.1.4.913","allowedAttributes" },
			{ "1.2.840.113556.1.4.914","allowedAttributesEffective" },
			{ "1.2.840.113556.1.4.915","possibleInferiors" },
			{ "1.2.840.113556.1.4.916","canonicalName" },
			{ "1.2.840.113556.1.4.917","mSMQQueueType" },
			{ "1.2.840.113556.1.4.918","mSMQJournal" },
			{ "1.2.840.113556.1.4.919","mSMQQuota" },
			{ "1.2.840.113556.1.4.920","mSMQBasePriority" },
			{ "1.2.840.113556.1.4.921","mSMQJournalQuota" },
			{ "1.2.840.113556.1.4.922","mSMQLabel" },
			{ "1.2.840.113556.1.4.923","mSMQAuthenticate" },
			{ "1.2.840.113556.1.4.924","mSMQPrivacyLevel" },
			{ "1.2.840.113556.1.4.925","mSMQOwnerID" },
			{ "1.2.840.113556.1.4.926","mSMQTransactional" },
			{ "1.2.840.113556.1.4.927","mSMQSites" },
			{ "1.2.840.113556.1.4.928","mSMQOutRoutingServers" },
			{ "1.2.840.113556.1.4.929","mSMQInRoutingServers" },
			{ "1.2.840.113556.1.4.93","pwdProperties" },
			{ "1.2.840.113556.1.4.930","mSMQServiceType" },
			{ "1.2.840.113556.1.4.933","mSMQComputerType" },
			{ "1.2.840.113556.1.4.934","mSMQForeign" },
			{ "1.2.840.113556.1.4.935","mSMQOSType" },
			{ "1.2.840.113556.1.4.936","mSMQEncryptKey" },
			{ "1.2.840.113556.1.4.937","mSMQSignKey" },
			{ "1.2.840.113556.1.4.939","mSMQNameStyle" },
			{ "1.2.840.113556.1.4.94","ntPwdHistory" },
			{ "1.2.840.113556.1.4.940","mSMQCSPName" },
			{ "1.2.840.113556.1.4.941","mSMQLongLived" },
			{ "1.2.840.113556.1.4.942","mSMQVersion" },
			{ "1.2.840.113556.1.4.943","mSMQSite1" },
			{ "1.2.840.113556.1.4.944","mSMQSite2" },
			{ "1.2.840.113556.1.4.945","mSMQSiteGates" },
			{ "1.2.840.113556.1.4.946","mSMQCost" },
			{ "1.2.840.113556.1.4.947","mSMQSignCertificates" },
			{ "1.2.840.113556.1.4.948","mSMQDigests" },
			{ "1.2.840.113556.1.4.95","pwdHistoryLength" },
			{ "1.2.840.113556.1.4.950","mSMQServices" },
			{ "1.2.840.113556.1.4.951","mSMQQMID" },
			{ "1.2.840.113556.1.4.952","mSMQMigrated" },
			{ "1.2.840.113556.1.4.953","mSMQSiteID" },
			{ "1.2.840.113556.1.4.96","pwdLastSet" },
			{ "1.2.840.113556.1.4.960","mSMQNt4Stub" },
			{ "1.2.840.113556.1.4.961","mSMQSiteForeign" },
			{ "1.2.840.113556.1.4.962","mSMQQueueQuota" },
			{ "1.2.840.113556.1.4.963","mSMQQueueJournalQuota" },
			{ "1.2.840.113556.1.4.964","mSMQNt4Flags" },
			{ "1.2.840.113556.1.4.965","mSMQSiteName" },
			{ "1.2.840.113556.1.4.966","mSMQDigestsMig" },
			{ "1.2.840.113556.1.4.967","mSMQSignCertificatesMig" },
			{ "1.2.840.113556.1.4.97","preferredOU" },
			{ "1.2.840.113556.1.4.98","primaryGroupID" },
			{ "1.2.840.113556.1.4.99","priorSetTime" },
			{ "1.2.840.113556.1.6.13.3.1","msDFSR-Version" },
			{ "1.2.840.113556.1.6.13.3.10","msDFSR-ReplicationGroupType" },
			{ "1.2.840.113556.1.6.13.3.100","msDFSR-MemberReference" },
			{ "1.2.840.113556.1.6.13.3.101","msDFSR-ComputerReference" },
			{ "1.2.840.113556.1.6.13.3.102","msDFSR-MemberReferenceBL" },
			{ "1.2.840.113556.1.6.13.3.103","msDFSR-ComputerReferenceBL" },
			{ "1.2.840.113556.1.6.13.3.11","msDFSR-TombstoneExpiryInMin" },
			{ "1.2.840.113556.1.6.13.3.12","msDFSR-FileFilter" },
			{ "1.2.840.113556.1.6.13.3.13","msDFSR-DirectoryFilter" },
			{ "1.2.840.113556.1.6.13.3.14","msDFSR-Schedule" },
			{ "1.2.840.113556.1.6.13.3.15","msDFSR-Keywords" },
			{ "1.2.840.113556.1.6.13.3.16","msDFSR-Flags" },
			{ "1.2.840.113556.1.6.13.3.17","msDFSR-Options" },
			{ "1.2.840.113556.1.6.13.3.18","msDFSR-ContentSetGuid" },
			{ "1.2.840.113556.1.6.13.3.19","msDFSR-RdcEnabled" },
			{ "1.2.840.113556.1.6.13.3.2","msDFSR-Extension" },
			{ "1.2.840.113556.1.6.13.3.20","msDFSR-RdcMinFileSizeInKb" },
			{ "1.2.840.113556.1.6.13.3.21","msDFSR-DfsPath" },
			{ "1.2.840.113556.1.6.13.3.22","msDFSR-RootFence" },
			{ "1.2.840.113556.1.6.13.3.23","msDFSR-ReplicationGroupGuid" },
			{ "1.2.840.113556.1.6.13.3.24","msDFSR-DfsLinkTarget" },
			{ "1.2.840.113556.1.6.13.3.25","msDFSR-Priority" },
			{ "1.2.840.113556.1.6.13.3.26","msDFSR-DeletedPath" },
			{ "1.2.840.113556.1.6.13.3.27","msDFSR-DeletedSizeInMb" },
			{ "1.2.840.113556.1.6.13.3.28","msDFSR-ReadOnly" },
			{ "1.2.840.113556.1.6.13.3.29","msDFSR-CachePolicy" },
			{ "1.2.840.113556.1.6.13.3.3","msDFSR-RootPath" },
			{ "1.2.840.113556.1.6.13.3.30","msDFSR-MinDurationCacheInMin" },
			{ "1.2.840.113556.1.6.13.3.31","msDFSR-MaxAgeInCacheInMin" },
			{ "1.2.840.113556.1.6.13.3.32","msDFSR-DisablePacketPrivacy" },
			{ "1.2.840.113556.1.6.13.3.34","msDFSR-DefaultCompressionExclusionFilter" },
			{ "1.2.840.113556.1.6.13.3.35","msDFSR-OnDemandExclusionFileFilter" },
			{ "1.2.840.113556.1.6.13.3.36","msDFSR-OnDemandExclusionDirectoryFilter" },
			{ "1.2.840.113556.1.6.13.3.37","msDFSR-Options2" },
			{ "1.2.840.113556.1.6.13.3.38","msDFSR-CommonStagingPath" },
			{ "1.2.840.113556.1.6.13.3.39","msDFSR-CommonStagingSizeInMb" },
			{ "1.2.840.113556.1.6.13.3.4","msDFSR-RootSizeInMb" },
			{ "1.2.840.113556.1.6.13.3.40","msDFSR-StagingCleanupTriggerInPercent" },
			{ "1.2.840.113556.1.6.13.3.5","msDFSR-StagingPath" },
			{ "1.2.840.113556.1.6.13.3.6","msDFSR-StagingSizeInMb" },
			{ "1.2.840.113556.1.6.13.3.7","msDFSR-ConflictPath" },
			{ "1.2.840.113556.1.6.13.3.8","msDFSR-ConflictSizeInMb" },
			{ "1.2.840.113556.1.6.13.3.9","msDFSR-Enabled" },
			{ "1.2.840.113556.1.6.18.1.300","msSFU30SearchContainer" },
			{ "1.2.840.113556.1.6.18.1.301","msSFU30KeyAttributes" },
			{ "1.2.840.113556.1.6.18.1.302","msSFU30FieldSeparator" },
			{ "1.2.840.113556.1.6.18.1.303","msSFU30IntraFieldSeparator" },
			{ "1.2.840.113556.1.6.18.1.304","msSFU30SearchAttributes" },
			{ "1.2.840.113556.1.6.18.1.305","msSFU30ResultAttributes" },
			{ "1.2.840.113556.1.6.18.1.306","msSFU30MapFilter" },
			{ "1.2.840.113556.1.6.18.1.307","msSFU30MasterServerName" },
			{ "1.2.840.113556.1.6.18.1.308","msSFU30OrderNumber" },
			{ "1.2.840.113556.1.6.18.1.309","msSFU30Name" },
			{ "1.2.840.113556.1.6.18.1.323","msSFU30Aliases" },
			{ "1.2.840.113556.1.6.18.1.324","msSFU30KeyValues" },
			{ "1.2.840.113556.1.6.18.1.339","msSFU30NisDomain" },
			{ "1.2.840.113556.1.6.18.1.340","msSFU30Domains" },
			{ "1.2.840.113556.1.6.18.1.341","msSFU30YpServers" },
			{ "1.2.840.113556.1.6.18.1.342","msSFU30MaxGidNumber" },
			{ "1.2.840.113556.1.6.18.1.343","msSFU30MaxUidNumber" },
			{ "1.2.840.113556.1.6.18.1.345","msSFU30NSMAPFieldPosition" },
			{ "1.2.840.113556.1.6.18.1.346","msSFU30PosixMember" },
			{ "1.2.840.113556.1.6.18.1.347","msSFU30PosixMemberOf" },
			{ "1.2.840.113556.1.6.18.1.348","msSFU30NetgroupHostAtDomain" },
			{ "1.2.840.113556.1.6.18.1.349","msSFU30NetgroupUserAtDomain" },
			{ "1.2.840.113556.1.6.18.1.350","msSFU30IsValidContainer" },
			{ "1.2.840.113556.1.6.18.1.352","msSFU30CryptMethod" },
			{ "1.3.6.1.1.1.1.0","uidNumber" },
			{ "1.3.6.1.1.1.1.1","gidNumber" },
			{ "1.3.6.1.1.1.1.10","shadowExpire" },
			{ "1.3.6.1.1.1.1.11","shadowFlag" },
			{ "1.3.6.1.1.1.1.12","memberUid" },
			{ "1.3.6.1.1.1.1.13","memberNisNetgroup" },
			{ "1.3.6.1.1.1.1.14","nisNetgroupTriple" },
			{ "1.3.6.1.1.1.1.15","ipServicePort" },
			{ "1.3.6.1.1.1.1.16","ipServiceProtocol" },
			{ "1.3.6.1.1.1.1.17","ipProtocolNumber" },
			{ "1.3.6.1.1.1.1.18","oncRpcNumber" },
			{ "1.3.6.1.1.1.1.19","ipHostNumber" },
			{ "1.3.6.1.1.1.1.2","gecos" },
			{ "1.3.6.1.1.1.1.20","ipNetworkNumber" },
			{ "1.3.6.1.1.1.1.21","ipNetmaskNumber" },
			{ "1.3.6.1.1.1.1.22","macAddress" },
			{ "1.3.6.1.1.1.1.23","bootParameter" },
			{ "1.3.6.1.1.1.1.24","bootFile" },
			{ "1.3.6.1.1.1.1.26","nisMapName" },
			{ "1.3.6.1.1.1.1.27","nisMapEntry" },
			{ "1.3.6.1.1.1.1.3","unixHomeDirectory" },
			{ "1.3.6.1.1.1.1.4","loginShell" },
			{ "1.3.6.1.1.1.1.5","shadowLastChange" },
			{ "1.3.6.1.1.1.1.6","shadowMin" },
			{ "1.3.6.1.1.1.1.7","shadowMax" },
			{ "1.3.6.1.1.1.1.8","shadowWarning" },
			{ "1.3.6.1.1.1.1.9","shadowInactive" },
			{ "1.3.6.1.4.1.1466.101.119.3","entryTTL" },
			{ "1.3.6.1.4.1.250.1.57","labeledURI" },
			{ "2.16.840.1.113730.3.1.1","carLicense" },
			{ "2.16.840.1.113730.3.1.2","departmentNumber" },
			{ "2.16.840.1.113730.3.1.216","userPKCS12" },
			{ "2.16.840.1.113730.3.1.34","middleName" },
			{ "2.16.840.1.113730.3.1.35","thumbnailPhoto" },
			{ "2.16.840.1.113730.3.1.36","thumbnailLogo" },
			{ "2.16.840.1.113730.3.1.39","preferredLanguage" },
			{ "2.16.840.1.113730.3.140","userSMIMECertificate" },
			{ "2.5.18.1","createTimeStamp" },
			{ "2.5.18.10","subSchemaSubEntry" },
			{ "2.5.18.2","modifyTimeStamp" },
			{ "2.5.21.2","dITContentRules" },
			{ "2.5.21.5","attributeTypes" },
			{ "2.5.21.6","objectClasses" },
			{ "2.5.21.9","structuralObjectClass" },
			{ "2.5.4.0","objectClass" },
			{ "2.5.4.10","o" },
			{ "2.5.4.11","ou" },
			{ "2.5.4.12","title" },
			{ "2.5.4.13","description" },
			{ "2.5.4.14","searchGuide" },
			{ "2.5.4.15","businessCategory" },
			{ "2.5.4.16","postalAddress" },
			{ "2.5.4.17","postalCode" },
			{ "2.5.4.18","postOfficeBox" },
			{ "2.5.4.19","physicalDeliveryOfficeName" },
			{ "2.5.4.2","knowledgeInformation" },
			{ "2.5.4.20","telephoneNumber" },
			{ "2.5.4.21","telexNumber" },
			{ "2.5.4.22","teletexTerminalIdentifier" },
			{ "2.5.4.23","facsimileTelephoneNumber" },
			{ "2.5.4.24","x121Address" },
			{ "2.5.4.25","internationalISDNNumber" },
			{ "2.5.4.26","registeredAddress" },
			{ "2.5.4.27","destinationIndicator" },
			{ "2.5.4.28","preferredDeliveryMethod" },
			{ "2.5.4.29","presentationAddress" },
			{ "2.5.4.3","cn" },
			{ "2.5.4.30","supportedApplicationContext" },
			{ "2.5.4.31","member" },
			{ "2.5.4.32","owner" },
			{ "2.5.4.33","roleOccupant" },
			{ "2.5.4.34","seeAlso" },
			{ "2.5.4.35","userPassword" },
			{ "2.5.4.36","userCertificate" },
			{ "2.5.4.37","cACertificate" },
			{ "2.5.4.38","authorityRevocationList" },
			{ "2.5.4.39","certificateRevocationList" },
			{ "2.5.4.4","sn" },
			{ "2.5.4.40","crossCertificatePair" },
			{ "2.5.4.42","givenName" },
			{ "2.5.4.43","initials" },
			{ "2.5.4.44","generationQualifier" },
			{ "2.5.4.45","x500uniqueIdentifier" },
			{ "2.5.4.49","distinguishedName" },
			{ "2.5.4.5","serialNumber" },
			{ "2.5.4.50","uniqueMember" },
			{ "2.5.4.51","houseIdentifier" },
			{ "2.5.4.53","deltaRevocationList" },
			{ "2.5.4.58","attributeCertificateAttribute" },
			{ "2.5.4.6","c" },
			{ "2.5.4.7","l" },
			{ "2.5.4.8","st" },
			{ "2.5.4.9","street" },
		};

		/// <summary>
		/// This Dictionary defines Name->Context object mappings for all defined LDAP Attributes that Microsoft Active Directory supports.
		/// Source: https://github.com/MicrosoftDocs/win32/tree/docs/desktop-src/ADSchema
		/// </summary>
		public static readonly IReadOnlyDictionary<string, LdapAttributeContext> ldapAttributeContextDict = new Dictionary<string, LdapAttributeContext>(StringComparer.OrdinalIgnoreCase)
		{
			{ "accountExpires", new LdapAttributeContext("accountExpires","1.2.840.113556.1.4.159",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "accountNameHistory", new LdapAttributeContext("accountNameHistory","1.2.840.113556.1.4.1307",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSAggregateTokenRatePerUser", new LdapAttributeContext("aCSAggregateTokenRatePerUser","1.2.840.113556.1.4.760",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSAllocableRSVPBandwidth", new LdapAttributeContext("aCSAllocableRSVPBandwidth","1.2.840.113556.1.4.766",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSCacheTimeout", new LdapAttributeContext("aCSCacheTimeout","1.2.840.113556.1.4.779",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSDirection", new LdapAttributeContext("aCSDirection","1.2.840.113556.1.4.757",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSDSBMDeadTime", new LdapAttributeContext("aCSDSBMDeadTime","1.2.840.113556.1.4.778",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSDSBMPriority", new LdapAttributeContext("aCSDSBMPriority","1.2.840.113556.1.4.776",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSDSBMRefresh", new LdapAttributeContext("aCSDSBMRefresh","1.2.840.113556.1.4.777",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSEnableACSService", new LdapAttributeContext("aCSEnableACSService","1.2.840.113556.1.4.770",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "aCSEnableRSVPAccounting", new LdapAttributeContext("aCSEnableRSVPAccounting","1.2.840.113556.1.4.899",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "aCSEnableRSVPMessageLogging", new LdapAttributeContext("aCSEnableRSVPMessageLogging","1.2.840.113556.1.4.768",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "aCSEventLogLevel", new LdapAttributeContext("aCSEventLogLevel","1.2.840.113556.1.4.769",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSIdentityName", new LdapAttributeContext("aCSIdentityName","1.2.840.113556.1.4.784",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSMaxAggregatePeakRatePerUser", new LdapAttributeContext("aCSMaxAggregatePeakRatePerUser","1.2.840.113556.1.4.897",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMaxDurationPerFlow", new LdapAttributeContext("aCSMaxDurationPerFlow","1.2.840.113556.1.4.761",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSMaximumSDUSize", new LdapAttributeContext("aCSMaximumSDUSize","1.2.840.113556.1.4.1314",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMaxNoOfAccountFiles", new LdapAttributeContext("aCSMaxNoOfAccountFiles","1.2.840.113556.1.4.901",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSMaxNoOfLogFiles", new LdapAttributeContext("aCSMaxNoOfLogFiles","1.2.840.113556.1.4.774",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSMaxPeakBandwidth", new LdapAttributeContext("aCSMaxPeakBandwidth","1.2.840.113556.1.4.767",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMaxPeakBandwidthPerFlow", new LdapAttributeContext("aCSMaxPeakBandwidthPerFlow","1.2.840.113556.1.4.759",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMaxSizeOfRSVPAccountFile", new LdapAttributeContext("aCSMaxSizeOfRSVPAccountFile","1.2.840.113556.1.4.902",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSMaxSizeOfRSVPLogFile", new LdapAttributeContext("aCSMaxSizeOfRSVPLogFile","1.2.840.113556.1.4.775",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSMaxTokenBucketPerFlow", new LdapAttributeContext("aCSMaxTokenBucketPerFlow","1.2.840.113556.1.4.1313",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMaxTokenRatePerFlow", new LdapAttributeContext("aCSMaxTokenRatePerFlow","1.2.840.113556.1.4.758",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMinimumDelayVariation", new LdapAttributeContext("aCSMinimumDelayVariation","1.2.840.113556.1.4.1317",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMinimumLatency", new LdapAttributeContext("aCSMinimumLatency","1.2.840.113556.1.4.1316",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSMinimumPolicedSize", new LdapAttributeContext("aCSMinimumPolicedSize","1.2.840.113556.1.4.1315",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedMaxSDUSize", new LdapAttributeContext("aCSNonReservedMaxSDUSize","1.2.840.113556.1.4.1320",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedMinPolicedSize", new LdapAttributeContext("aCSNonReservedMinPolicedSize","1.2.840.113556.1.4.1321",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedPeakRate", new LdapAttributeContext("aCSNonReservedPeakRate","1.2.840.113556.1.4.1318",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedTokenSize", new LdapAttributeContext("aCSNonReservedTokenSize","1.2.840.113556.1.4.1319",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedTxLimit", new LdapAttributeContext("aCSNonReservedTxLimit","1.2.840.113556.1.4.780",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSNonReservedTxSize", new LdapAttributeContext("aCSNonReservedTxSize","1.2.840.113556.1.4.898",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSPermissionBits", new LdapAttributeContext("aCSPermissionBits","1.2.840.113556.1.4.765",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "aCSPolicyName", new LdapAttributeContext("aCSPolicyName","1.2.840.113556.1.4.772",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSPriority", new LdapAttributeContext("aCSPriority","1.2.840.113556.1.4.764",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSRSVPAccountFilesLocation", new LdapAttributeContext("aCSRSVPAccountFilesLocation","1.2.840.113556.1.4.900",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSRSVPLogFilesLocation", new LdapAttributeContext("aCSRSVPLogFilesLocation","1.2.840.113556.1.4.773",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSServerList", new LdapAttributeContext("aCSServerList","1.2.840.113556.1.4.1312",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSServiceType", new LdapAttributeContext("aCSServiceType","1.2.840.113556.1.4.762",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "aCSTimeOfDay", new LdapAttributeContext("aCSTimeOfDay","1.2.840.113556.1.4.756",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aCSTotalNoOfFlows", new LdapAttributeContext("aCSTotalNoOfFlows","1.2.840.113556.1.4.763",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "additionalTrustedServiceNames", new LdapAttributeContext("additionalTrustedServiceNames","1.2.840.113556.1.4.889",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "addressBookRoots", new LdapAttributeContext("addressBookRoots","1.2.840.113556.1.4.1244",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "addressBookRoots2", new LdapAttributeContext("addressBookRoots2","1.2.840.113556.1.4.2046",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "addressEntryDisplayTable", new LdapAttributeContext("addressEntryDisplayTable","1.2.840.113556.1.2.324",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "addressEntryDisplayTableMSDOS", new LdapAttributeContext("addressEntryDisplayTableMSDOS","1.2.840.113556.1.2.400",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "addressSyntax", new LdapAttributeContext("addressSyntax","1.2.840.113556.1.2.255",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "addressType", new LdapAttributeContext("addressType","1.2.840.113556.1.2.350",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "adminContextMenu", new LdapAttributeContext("adminContextMenu","1.2.840.113556.1.4.614",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "adminCount", new LdapAttributeContext("adminCount","1.2.840.113556.1.4.150",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "adminDescription", new LdapAttributeContext("adminDescription","1.2.840.113556.1.2.226",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "adminDisplayName", new LdapAttributeContext("adminDisplayName","1.2.840.113556.1.2.194",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "adminMultiselectPropertyPages", new LdapAttributeContext("adminMultiselectPropertyPages","1.2.840.113556.1.4.1690",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "adminPropertyPages", new LdapAttributeContext("adminPropertyPages","1.2.840.113556.1.4.562",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "allowedAttributes", new LdapAttributeContext("allowedAttributes","1.2.840.113556.1.4.913",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "allowedAttributesEffective", new LdapAttributeContext("allowedAttributesEffective","1.2.840.113556.1.4.914",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "allowedChildClasses", new LdapAttributeContext("allowedChildClasses","1.2.840.113556.1.4.911",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "allowedChildClassesEffective", new LdapAttributeContext("allowedChildClassesEffective","1.2.840.113556.1.4.912",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "altSecurityIdentities", new LdapAttributeContext("altSecurityIdentities","1.2.840.113556.1.4.867",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "aNR", new LdapAttributeContext("aNR","1.2.840.113556.1.4.1208",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "applicationName", new LdapAttributeContext("applicationName","1.2.840.113556.1.4.218",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "appliesTo", new LdapAttributeContext("appliesTo","1.2.840.113556.1.4.341",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "appSchemaVersion", new LdapAttributeContext("appSchemaVersion","1.2.840.113556.1.4.848",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "assetNumber", new LdapAttributeContext("assetNumber","1.2.840.113556.1.4.283",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "assistant", new LdapAttributeContext("assistant","1.2.840.113556.1.4.652",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "associatedDomain", new LdapAttributeContext("associatedDomain","0.9.2342.19200300.100.1.37",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "associatedName", new LdapAttributeContext("associatedName","0.9.2342.19200300.100.1.38",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "assocNTAccount", new LdapAttributeContext("assocNTAccount","1.2.840.113556.1.4.1213",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "attributeCertificateAttribute", new LdapAttributeContext("attributeCertificateAttribute","2.5.4.58",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "attributeDisplayNames", new LdapAttributeContext("attributeDisplayNames","1.2.840.113556.1.4.748",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "attributeID", new LdapAttributeContext("attributeID","1.2.840.113556.1.2.30",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "attributeSecurityGUID", new LdapAttributeContext("attributeSecurityGUID","1.2.840.113556.1.4.149",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "attributeSyntax", new LdapAttributeContext("attributeSyntax","1.2.840.113556.1.2.32",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "attributeTypes", new LdapAttributeContext("attributeTypes","2.5.21.5",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "audio", new LdapAttributeContext("audio","0.9.2342.19200300.100.1.55",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "auditingPolicy", new LdapAttributeContext("auditingPolicy","1.2.840.113556.1.4.202",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "authenticationOptions", new LdapAttributeContext("authenticationOptions","1.2.840.113556.1.4.11",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "authorityRevocationList", new LdapAttributeContext("authorityRevocationList","2.5.4.38",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "auxiliaryClass", new LdapAttributeContext("auxiliaryClass","1.2.840.113556.1.2.351",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "badPasswordTime", new LdapAttributeContext("badPasswordTime","1.2.840.113556.1.4.49",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "badPwdCount", new LdapAttributeContext("badPwdCount","1.2.840.113556.1.4.12",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "birthLocation", new LdapAttributeContext("birthLocation","1.2.840.113556.1.4.332",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "bootFile", new LdapAttributeContext("bootFile","1.3.6.1.1.1.1.24",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "bootParameter", new LdapAttributeContext("bootParameter","1.3.6.1.1.1.1.23",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "bridgeheadServerListBL", new LdapAttributeContext("bridgeheadServerListBL","1.2.840.113556.1.4.820",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "bridgeheadTransportList", new LdapAttributeContext("bridgeheadTransportList","1.2.840.113556.1.4.819",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "buildingName", new LdapAttributeContext("buildingName","0.9.2342.19200300.100.1.48",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "builtinCreationTime", new LdapAttributeContext("builtinCreationTime","1.2.840.113556.1.4.13",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "builtinModifiedCount", new LdapAttributeContext("builtinModifiedCount","1.2.840.113556.1.4.14",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "businessCategory", new LdapAttributeContext("businessCategory","2.5.4.15",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "bytesPerMinute", new LdapAttributeContext("bytesPerMinute","1.2.840.113556.1.4.284",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "c", new LdapAttributeContext("c","2.5.4.6",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cACertificate", new LdapAttributeContext("cACertificate","2.5.4.37",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "cACertificateDN", new LdapAttributeContext("cACertificateDN","1.2.840.113556.1.4.697",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cAConnect", new LdapAttributeContext("cAConnect","1.2.840.113556.1.4.687",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "canonicalName", new LdapAttributeContext("canonicalName","1.2.840.113556.1.4.916",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "canUpgradeScript", new LdapAttributeContext("canUpgradeScript","1.2.840.113556.1.4.815",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "carLicense", new LdapAttributeContext("carLicense","2.16.840.1.113730.3.1.1",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "catalogs", new LdapAttributeContext("catalogs","1.2.840.113556.1.4.675",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "categories", new LdapAttributeContext("categories","1.2.840.113556.1.4.672",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "categoryId", new LdapAttributeContext("categoryId","1.2.840.113556.1.4.322",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "cAUsages", new LdapAttributeContext("cAUsages","1.2.840.113556.1.4.690",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cAWEBURL", new LdapAttributeContext("cAWEBURL","1.2.840.113556.1.4.688",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "certificateAuthorityObject", new LdapAttributeContext("certificateAuthorityObject","1.2.840.113556.1.4.684",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "certificateRevocationList", new LdapAttributeContext("certificateRevocationList","2.5.4.39",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "certificateTemplates", new LdapAttributeContext("certificateTemplates","1.2.840.113556.1.4.823",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "classDisplayName", new LdapAttributeContext("classDisplayName","1.2.840.113556.1.4.610",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cn", new LdapAttributeContext("cn","2.5.4.3",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "co", new LdapAttributeContext("co","1.2.840.113556.1.2.131",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "codePage", new LdapAttributeContext("codePage","1.2.840.113556.1.4.16",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "cOMClassID", new LdapAttributeContext("cOMClassID","1.2.840.113556.1.4.19",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMCLSID", new LdapAttributeContext("cOMCLSID","1.2.840.113556.1.4.249",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMInterfaceID", new LdapAttributeContext("cOMInterfaceID","1.2.840.113556.1.4.20",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "comment", new LdapAttributeContext("comment","1.2.840.113556.1.4.156",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMOtherProgId", new LdapAttributeContext("cOMOtherProgId","1.2.840.113556.1.4.253",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "company", new LdapAttributeContext("company","1.2.840.113556.1.2.146",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMProgID", new LdapAttributeContext("cOMProgID","1.2.840.113556.1.4.21",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMTreatAsClassId", new LdapAttributeContext("cOMTreatAsClassId","1.2.840.113556.1.4.251",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMTypelibId", new LdapAttributeContext("cOMTypelibId","1.2.840.113556.1.4.254",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cOMUniqueLIBID", new LdapAttributeContext("cOMUniqueLIBID","1.2.840.113556.1.4.250",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "contentIndexingAllowed", new LdapAttributeContext("contentIndexingAllowed","1.2.840.113556.1.4.24",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "contextMenu", new LdapAttributeContext("contextMenu","1.2.840.113556.1.4.499",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "controlAccessRights", new LdapAttributeContext("controlAccessRights","1.2.840.113556.1.4.200",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "cost", new LdapAttributeContext("cost","1.2.840.113556.1.2.135",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "countryCode", new LdapAttributeContext("countryCode","1.2.840.113556.1.4.25",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "createDialog", new LdapAttributeContext("createDialog","1.2.840.113556.1.4.810",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "createTimeStamp", new LdapAttributeContext("createTimeStamp","2.5.18.1",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "createWizardExt", new LdapAttributeContext("createWizardExt","1.2.840.113556.1.4.812",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "creationTime", new LdapAttributeContext("creationTime","1.2.840.113556.1.4.26",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "creationWizard", new LdapAttributeContext("creationWizard","1.2.840.113556.1.4.498",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "creator", new LdapAttributeContext("creator","1.2.840.113556.1.4.679",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "cRLObject", new LdapAttributeContext("cRLObject","1.2.840.113556.1.4.689",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "cRLPartitionedRevocationList", new LdapAttributeContext("cRLPartitionedRevocationList","1.2.840.113556.1.4.683",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "crossCertificatePair", new LdapAttributeContext("crossCertificatePair","2.5.4.40",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "currentLocation", new LdapAttributeContext("currentLocation","1.2.840.113556.1.4.335",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "currentParentCA", new LdapAttributeContext("currentParentCA","1.2.840.113556.1.4.696",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "currentValue", new LdapAttributeContext("currentValue","1.2.840.113556.1.4.27",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "currMachineId", new LdapAttributeContext("currMachineId","1.2.840.113556.1.4.337",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dBCSPwd", new LdapAttributeContext("dBCSPwd","1.2.840.113556.1.4.55",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dc", new LdapAttributeContext("dc","0.9.2342.19200300.100.1.25",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "defaultClassStore", new LdapAttributeContext("defaultClassStore","1.2.840.113556.1.4.213",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "defaultGroup", new LdapAttributeContext("defaultGroup","1.2.840.113556.1.4.480",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "defaultHidingValue", new LdapAttributeContext("defaultHidingValue","1.2.840.113556.1.4.518",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "defaultLocalPolicyObject", new LdapAttributeContext("defaultLocalPolicyObject","1.2.840.113556.1.4.57",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "defaultObjectCategory", new LdapAttributeContext("defaultObjectCategory","1.2.840.113556.1.4.783",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "defaultPriority", new LdapAttributeContext("defaultPriority","1.2.840.113556.1.4.232",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "defaultSecurityDescriptor", new LdapAttributeContext("defaultSecurityDescriptor","1.2.840.113556.1.4.224",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "deltaRevocationList", new LdapAttributeContext("deltaRevocationList","2.5.4.53",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "department", new LdapAttributeContext("department","1.2.840.113556.1.2.141",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "departmentNumber", new LdapAttributeContext("departmentNumber","2.16.840.1.113730.3.1.2",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "description", new LdapAttributeContext("description","2.5.4.13",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "desktopProfile", new LdapAttributeContext("desktopProfile","1.2.840.113556.1.4.346",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "destinationIndicator", new LdapAttributeContext("destinationIndicator","2.5.4.27",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpClasses", new LdapAttributeContext("dhcpClasses","1.2.840.113556.1.4.715",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dhcpFlags", new LdapAttributeContext("dhcpFlags","1.2.840.113556.1.4.700",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "dhcpIdentification", new LdapAttributeContext("dhcpIdentification","1.2.840.113556.1.4.701",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dhcpMask", new LdapAttributeContext("dhcpMask","1.2.840.113556.1.4.706",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpMaxKey", new LdapAttributeContext("dhcpMaxKey","1.2.840.113556.1.4.719",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "dhcpObjDescription", new LdapAttributeContext("dhcpObjDescription","1.2.840.113556.1.4.703",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dhcpObjName", new LdapAttributeContext("dhcpObjName","1.2.840.113556.1.4.702",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dhcpOptions", new LdapAttributeContext("dhcpOptions","1.2.840.113556.1.4.714",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dhcpProperties", new LdapAttributeContext("dhcpProperties","1.2.840.113556.1.4.718",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dhcpRanges", new LdapAttributeContext("dhcpRanges","1.2.840.113556.1.4.707",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpReservations", new LdapAttributeContext("dhcpReservations","1.2.840.113556.1.4.709",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpServers", new LdapAttributeContext("dhcpServers","1.2.840.113556.1.4.704",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpSites", new LdapAttributeContext("dhcpSites","1.2.840.113556.1.4.708",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpState", new LdapAttributeContext("dhcpState","1.2.840.113556.1.4.717",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpSubnets", new LdapAttributeContext("dhcpSubnets","1.2.840.113556.1.4.705",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "dhcpType", new LdapAttributeContext("dhcpType","1.2.840.113556.1.4.699",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dhcpUniqueKey", new LdapAttributeContext("dhcpUniqueKey","1.2.840.113556.1.4.698",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "dhcpUpdateTime", new LdapAttributeContext("dhcpUpdateTime","1.2.840.113556.1.4.720",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "directReports", new LdapAttributeContext("directReports","1.2.840.113556.1.2.436",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "displayName", new LdapAttributeContext("displayName","1.2.840.113556.1.2.13",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "displayNamePrintable", new LdapAttributeContext("displayNamePrintable","1.2.840.113556.1.2.353",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "distinguishedName", new LdapAttributeContext("distinguishedName","2.5.4.49",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "dITContentRules", new LdapAttributeContext("dITContentRules","2.5.21.2",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "division", new LdapAttributeContext("division","1.2.840.113556.1.4.261",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dMDLocation", new LdapAttributeContext("dMDLocation","1.2.840.113556.1.2.36",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "dmdName", new LdapAttributeContext("dmdName","1.2.840.113556.1.2.598",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dNReferenceUpdate", new LdapAttributeContext("dNReferenceUpdate","1.2.840.113556.1.4.1242",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "dnsAllowDynamic", new LdapAttributeContext("dnsAllowDynamic","1.2.840.113556.1.4.378",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "dnsAllowXFR", new LdapAttributeContext("dnsAllowXFR","1.2.840.113556.1.4.379",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "dNSHostName", new LdapAttributeContext("dNSHostName","1.2.840.113556.1.4.619",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dnsNotifySecondaries", new LdapAttributeContext("dnsNotifySecondaries","1.2.840.113556.1.4.381",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dNSProperty", new LdapAttributeContext("dNSProperty","1.2.840.113556.1.4.1306",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dnsRecord", new LdapAttributeContext("dnsRecord","1.2.840.113556.1.4.382",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dnsRoot", new LdapAttributeContext("dnsRoot","1.2.840.113556.1.4.28",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dnsSecureSecondaries", new LdapAttributeContext("dnsSecureSecondaries","1.2.840.113556.1.4.380",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dNSTombstoned", new LdapAttributeContext("dNSTombstoned","1.2.840.113556.1.4.1414",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "documentAuthor", new LdapAttributeContext("documentAuthor","0.9.2342.19200300.100.1.14",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "documentIdentifier", new LdapAttributeContext("documentIdentifier","0.9.2342.19200300.100.1.11",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "documentLocation", new LdapAttributeContext("documentLocation","0.9.2342.19200300.100.1.15",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "documentPublisher", new LdapAttributeContext("documentPublisher","0.9.2342.19200300.100.1.56",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "documentTitle", new LdapAttributeContext("documentTitle","0.9.2342.19200300.100.1.12",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "documentVersion", new LdapAttributeContext("documentVersion","0.9.2342.19200300.100.1.13",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "domainCAs", new LdapAttributeContext("domainCAs","1.2.840.113556.1.4.668",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "domainCrossRef", new LdapAttributeContext("domainCrossRef","1.2.840.113556.1.4.472",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "domainID", new LdapAttributeContext("domainID","1.2.840.113556.1.4.686",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "domainIdentifier", new LdapAttributeContext("domainIdentifier","1.2.840.113556.1.4.755",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "domainPolicyObject", new LdapAttributeContext("domainPolicyObject","1.2.840.113556.1.4.32",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "domainPolicyReference", new LdapAttributeContext("domainPolicyReference","1.2.840.113556.1.4.422",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "domainReplica", new LdapAttributeContext("domainReplica","1.2.840.113556.1.4.158",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "domainWidePolicy", new LdapAttributeContext("domainWidePolicy","1.2.840.113556.1.4.421",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "drink", new LdapAttributeContext("drink","0.9.2342.19200300.100.1.5",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "driverName", new LdapAttributeContext("driverName","1.2.840.113556.1.4.229",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "driverVersion", new LdapAttributeContext("driverVersion","1.2.840.113556.1.4.276",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dSASignature", new LdapAttributeContext("dSASignature","1.2.840.113556.1.2.74",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "dSCorePropagationData", new LdapAttributeContext("dSCorePropagationData","1.2.840.113556.1.4.1357",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "dSHeuristics", new LdapAttributeContext("dSHeuristics","1.2.840.113556.1.2.212",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dSUIAdminMaximum", new LdapAttributeContext("dSUIAdminMaximum","1.2.840.113556.1.4.1344",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dSUIAdminNotification", new LdapAttributeContext("dSUIAdminNotification","1.2.840.113556.1.4.1343",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "dSUIShellMaximum", new LdapAttributeContext("dSUIShellMaximum","1.2.840.113556.1.4.1345",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "dynamicLDAPServer", new LdapAttributeContext("dynamicLDAPServer","1.2.840.113556.1.4.537",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "eFSPolicy", new LdapAttributeContext("eFSPolicy","1.2.840.113556.1.4.268",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "employeeID", new LdapAttributeContext("employeeID","1.2.840.113556.1.4.35",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "employeeNumber", new LdapAttributeContext("employeeNumber","1.2.840.113556.1.2.610",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "employeeType", new LdapAttributeContext("employeeType","1.2.840.113556.1.2.613",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "Enabled", new LdapAttributeContext("Enabled","1.2.840.113556.1.2.557",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "enabledConnection", new LdapAttributeContext("enabledConnection","1.2.840.113556.1.4.36",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "enrollmentProviders", new LdapAttributeContext("enrollmentProviders","1.2.840.113556.1.4.825",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "entryTTL", new LdapAttributeContext("entryTTL","1.3.6.1.4.1.1466.101.119.3",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "extendedAttributeInfo", new LdapAttributeContext("extendedAttributeInfo","1.2.840.113556.1.4.909",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "extendedCharsAllowed", new LdapAttributeContext("extendedCharsAllowed","1.2.840.113556.1.2.380",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "extendedClassInfo", new LdapAttributeContext("extendedClassInfo","1.2.840.113556.1.4.908",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "extensionName", new LdapAttributeContext("extensionName","1.2.840.113556.1.2.227",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "extraColumns", new LdapAttributeContext("extraColumns","1.2.840.113556.1.4.1687",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "facsimileTelephoneNumber", new LdapAttributeContext("facsimileTelephoneNumber","2.5.4.23",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fileExtPriority", new LdapAttributeContext("fileExtPriority","1.2.840.113556.1.4.816",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "flags", new LdapAttributeContext("flags","1.2.840.113556.1.4.38",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "flatName", new LdapAttributeContext("flatName","1.2.840.113556.1.4.511",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "forceLogoff", new LdapAttributeContext("forceLogoff","1.2.840.113556.1.4.39",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "foreignIdentifier", new LdapAttributeContext("foreignIdentifier","1.2.840.113556.1.4.356",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "friendlyNames", new LdapAttributeContext("friendlyNames","1.2.840.113556.1.4.682",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fromEntry", new LdapAttributeContext("fromEntry","1.2.840.113556.1.4.910",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "fromServer", new LdapAttributeContext("fromServer","1.2.840.113556.1.4.40",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "frsComputerReference", new LdapAttributeContext("frsComputerReference","1.2.840.113556.1.4.869",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "frsComputerReferenceBL", new LdapAttributeContext("frsComputerReferenceBL","1.2.840.113556.1.4.870",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "fRSControlDataCreation", new LdapAttributeContext("fRSControlDataCreation","1.2.840.113556.1.4.871",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSControlInboundBacklog", new LdapAttributeContext("fRSControlInboundBacklog","1.2.840.113556.1.4.872",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSControlOutboundBacklog", new LdapAttributeContext("fRSControlOutboundBacklog","1.2.840.113556.1.4.873",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSDirectoryFilter", new LdapAttributeContext("fRSDirectoryFilter","1.2.840.113556.1.4.484",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSDSPoll", new LdapAttributeContext("fRSDSPoll","1.2.840.113556.1.4.490",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSExtensions", new LdapAttributeContext("fRSExtensions","1.2.840.113556.1.4.536",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "fRSFaultCondition", new LdapAttributeContext("fRSFaultCondition","1.2.840.113556.1.4.491",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSFileFilter", new LdapAttributeContext("fRSFileFilter","1.2.840.113556.1.4.483",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSFlags", new LdapAttributeContext("fRSFlags","1.2.840.113556.1.4.874",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSLevelLimit", new LdapAttributeContext("fRSLevelLimit","1.2.840.113556.1.4.534",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSMemberReference", new LdapAttributeContext("fRSMemberReference","1.2.840.113556.1.4.875",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "fRSMemberReferenceBL", new LdapAttributeContext("fRSMemberReferenceBL","1.2.840.113556.1.4.876",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "fRSPartnerAuthLevel", new LdapAttributeContext("fRSPartnerAuthLevel","1.2.840.113556.1.4.877",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSPrimaryMember", new LdapAttributeContext("fRSPrimaryMember","1.2.840.113556.1.4.878",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "fRSReplicaSetGUID", new LdapAttributeContext("fRSReplicaSetGUID","1.2.840.113556.1.4.533",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "fRSReplicaSetType", new LdapAttributeContext("fRSReplicaSetType","1.2.840.113556.1.4.31",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSRootPath", new LdapAttributeContext("fRSRootPath","1.2.840.113556.1.4.487",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSRootSecurity", new LdapAttributeContext("fRSRootSecurity","1.2.840.113556.1.4.535",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "fRSServiceCommand", new LdapAttributeContext("fRSServiceCommand","1.2.840.113556.1.4.500",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSServiceCommandStatus", new LdapAttributeContext("fRSServiceCommandStatus","1.2.840.113556.1.4.879",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSStagingPath", new LdapAttributeContext("fRSStagingPath","1.2.840.113556.1.4.488",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSTimeLastCommand", new LdapAttributeContext("fRSTimeLastCommand","1.2.840.113556.1.4.880",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "fRSTimeLastConfigChange", new LdapAttributeContext("fRSTimeLastConfigChange","1.2.840.113556.1.4.881",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "fRSUpdateTimeout", new LdapAttributeContext("fRSUpdateTimeout","1.2.840.113556.1.4.485",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "fRSVersion", new LdapAttributeContext("fRSVersion","1.2.840.113556.1.4.882",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fRSVersionGUID", new LdapAttributeContext("fRSVersionGUID","1.2.840.113556.1.4.43",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "fRSWorkingPath", new LdapAttributeContext("fRSWorkingPath","1.2.840.113556.1.4.486",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "fSMORoleOwner", new LdapAttributeContext("fSMORoleOwner","1.2.840.113556.1.4.369",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "garbageCollPeriod", new LdapAttributeContext("garbageCollPeriod","1.2.840.113556.1.2.301",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "gecos", new LdapAttributeContext("gecos","1.3.6.1.1.1.1.2",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "generatedConnection", new LdapAttributeContext("generatedConnection","1.2.840.113556.1.4.41",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "generationQualifier", new LdapAttributeContext("generationQualifier","2.5.4.44",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gidNumber", new LdapAttributeContext("gidNumber","1.3.6.1.1.1.1.1",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "givenName", new LdapAttributeContext("givenName","2.5.4.42",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "globalAddressList", new LdapAttributeContext("globalAddressList","1.2.840.113556.1.4.1245",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "globalAddressList2", new LdapAttributeContext("globalAddressList2","1.2.840.113556.1.4.2047",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "governsID", new LdapAttributeContext("governsID","1.2.840.113556.1.2.22",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "gPCFileSysPath", new LdapAttributeContext("gPCFileSysPath","1.2.840.113556.1.4.894",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gPCFunctionalityVersion", new LdapAttributeContext("gPCFunctionalityVersion","1.2.840.113556.1.4.893",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "gPCMachineExtensionNames", new LdapAttributeContext("gPCMachineExtensionNames","1.2.840.113556.1.4.1348",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gPCUserExtensionNames", new LdapAttributeContext("gPCUserExtensionNames","1.2.840.113556.1.4.1349",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gPCWQLFilter", new LdapAttributeContext("gPCWQLFilter","1.2.840.113556.1.4.1694",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gPLink", new LdapAttributeContext("gPLink","1.2.840.113556.1.4.891",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "gPOptions", new LdapAttributeContext("gPOptions","1.2.840.113556.1.4.892",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "groupAttributes", new LdapAttributeContext("groupAttributes","1.2.840.113556.1.4.152",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "groupMembershipSAM", new LdapAttributeContext("groupMembershipSAM","1.2.840.113556.1.4.166",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "groupPriority", new LdapAttributeContext("groupPriority","1.2.840.113556.1.4.345",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "groupsToIgnore", new LdapAttributeContext("groupsToIgnore","1.2.840.113556.1.4.344",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "groupType", new LdapAttributeContext("groupType","1.2.840.113556.1.4.750",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "hasMasterNCs", new LdapAttributeContext("hasMasterNCs","1.2.840.113556.1.2.14",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "hasPartialReplicaNCs", new LdapAttributeContext("hasPartialReplicaNCs","1.2.840.113556.1.2.15",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "helpData16", new LdapAttributeContext("helpData16","1.2.840.113556.1.2.402",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "helpData32", new LdapAttributeContext("helpData32","1.2.840.113556.1.2.9",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "helpFileName", new LdapAttributeContext("helpFileName","1.2.840.113556.1.2.327",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "hideFromAB", new LdapAttributeContext("hideFromAB","1.2.840.113556.1.4.1780",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "homeDirectory", new LdapAttributeContext("homeDirectory","1.2.840.113556.1.4.44",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "homeDrive", new LdapAttributeContext("homeDrive","1.2.840.113556.1.4.45",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "homePhone", new LdapAttributeContext("homePhone","0.9.2342.19200300.100.1.20",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "homePostalAddress", new LdapAttributeContext("homePostalAddress","1.2.840.113556.1.2.617",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "host", new LdapAttributeContext("host","0.9.2342.19200300.100.1.9",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "houseIdentifier", new LdapAttributeContext("houseIdentifier","2.5.4.51",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "iconPath", new LdapAttributeContext("iconPath","1.2.840.113556.1.4.219",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "implementedCategories", new LdapAttributeContext("implementedCategories","1.2.840.113556.1.4.320",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "indexedScopes", new LdapAttributeContext("indexedScopes","1.2.840.113556.1.4.681",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "info", new LdapAttributeContext("info","1.2.840.113556.1.2.81",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "initialAuthIncoming", new LdapAttributeContext("initialAuthIncoming","1.2.840.113556.1.4.539",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "initialAuthOutgoing", new LdapAttributeContext("initialAuthOutgoing","1.2.840.113556.1.4.540",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "initials", new LdapAttributeContext("initials","2.5.4.43",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "installUiLevel", new LdapAttributeContext("installUiLevel","1.2.840.113556.1.4.847",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "instanceType", new LdapAttributeContext("instanceType","1.2.840.113556.1.2.1",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "internationalISDNNumber", new LdapAttributeContext("internationalISDNNumber","2.5.4.25",LdapTokenFormat.StringNumeric,"2.5.5.6",LdapAttributeSyntaxADSType.NumericString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Numeric,"A string that contains digits.") },
			{ "interSiteTopologyFailover", new LdapAttributeContext("interSiteTopologyFailover","1.2.840.113556.1.4.1248",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "interSiteTopologyGenerator", new LdapAttributeContext("interSiteTopologyGenerator","1.2.840.113556.1.4.1246",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "interSiteTopologyRenew", new LdapAttributeContext("interSiteTopologyRenew","1.2.840.113556.1.4.1247",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "invocationId", new LdapAttributeContext("invocationId","1.2.840.113556.1.2.115",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "ipHostNumber", new LdapAttributeContext("ipHostNumber","1.3.6.1.1.1.1.19",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "ipNetmaskNumber", new LdapAttributeContext("ipNetmaskNumber","1.3.6.1.1.1.1.21",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "ipNetworkNumber", new LdapAttributeContext("ipNetworkNumber","1.3.6.1.1.1.1.20",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "ipPhone", new LdapAttributeContext("ipPhone","1.2.840.113556.1.4.721",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ipProtocolNumber", new LdapAttributeContext("ipProtocolNumber","1.3.6.1.1.1.1.17",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ipsecData", new LdapAttributeContext("ipsecData","1.2.840.113556.1.4.623",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "ipsecDataType", new LdapAttributeContext("ipsecDataType","1.2.840.113556.1.4.622",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ipsecFilterReference", new LdapAttributeContext("ipsecFilterReference","1.2.840.113556.1.4.629",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ipsecID", new LdapAttributeContext("ipsecID","1.2.840.113556.1.4.621",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ipsecISAKMPReference", new LdapAttributeContext("ipsecISAKMPReference","1.2.840.113556.1.4.626",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ipsecName", new LdapAttributeContext("ipsecName","1.2.840.113556.1.4.620",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "iPSECNegotiationPolicyAction", new LdapAttributeContext("iPSECNegotiationPolicyAction","1.2.840.113556.1.4.888",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ipsecNegotiationPolicyReference", new LdapAttributeContext("ipsecNegotiationPolicyReference","1.2.840.113556.1.4.628",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "iPSECNegotiationPolicyType", new LdapAttributeContext("iPSECNegotiationPolicyType","1.2.840.113556.1.4.887",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ipsecNFAReference", new LdapAttributeContext("ipsecNFAReference","1.2.840.113556.1.4.627",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ipsecOwnersReference", new LdapAttributeContext("ipsecOwnersReference","1.2.840.113556.1.4.624",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ipsecPolicyReference", new LdapAttributeContext("ipsecPolicyReference","1.2.840.113556.1.4.517",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ipServicePort", new LdapAttributeContext("ipServicePort","1.3.6.1.1.1.1.15",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ipServiceProtocol", new LdapAttributeContext("ipServiceProtocol","1.3.6.1.1.1.1.16",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "isCriticalSystemObject", new LdapAttributeContext("isCriticalSystemObject","1.2.840.113556.1.4.868",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isDefunct", new LdapAttributeContext("isDefunct","1.2.840.113556.1.4.661",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isDeleted", new LdapAttributeContext("isDeleted","1.2.840.113556.1.2.48",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isEphemeral", new LdapAttributeContext("isEphemeral","1.2.840.113556.1.4.1212",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isMemberOfPartialAttributeSet", new LdapAttributeContext("isMemberOfPartialAttributeSet","1.2.840.113556.1.4.639",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isPrivilegeHolder", new LdapAttributeContext("isPrivilegeHolder","1.2.840.113556.1.4.638",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "isRecycled", new LdapAttributeContext("isRecycled","1.2.840.113556.1.4.2058",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "isSingleValued", new LdapAttributeContext("isSingleValued","1.2.840.113556.1.2.33",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "jpegPhoto", new LdapAttributeContext("jpegPhoto","0.9.2342.19200300.100.1.60",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "keywords", new LdapAttributeContext("keywords","1.2.840.113556.1.4.48",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "knowledgeInformation", new LdapAttributeContext("knowledgeInformation","2.5.4.2",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "l", new LdapAttributeContext("l","2.5.4.7",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "labeledURI", new LdapAttributeContext("labeledURI","1.3.6.1.4.1.250.1.57",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "lastBackupRestorationTime", new LdapAttributeContext("lastBackupRestorationTime","1.2.840.113556.1.4.519",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastContentIndexed", new LdapAttributeContext("lastContentIndexed","1.2.840.113556.1.4.50",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastKnownParent", new LdapAttributeContext("lastKnownParent","1.2.840.113556.1.4.781",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "lastLogoff", new LdapAttributeContext("lastLogoff","1.2.840.113556.1.4.51",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastLogon", new LdapAttributeContext("lastLogon","1.2.840.113556.1.4.52",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastLogonTimestamp", new LdapAttributeContext("lastLogonTimestamp","1.2.840.113556.1.4.1696",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastSetTime", new LdapAttributeContext("lastSetTime","1.2.840.113556.1.4.53",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lastUpdateSequence", new LdapAttributeContext("lastUpdateSequence","1.2.840.113556.1.4.330",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "lDAPAdminLimits", new LdapAttributeContext("lDAPAdminLimits","1.2.840.113556.1.4.843",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "lDAPDisplayName", new LdapAttributeContext("lDAPDisplayName","1.2.840.113556.1.2.460",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "lDAPIPDenyList", new LdapAttributeContext("lDAPIPDenyList","1.2.840.113556.1.4.844",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "legacyExchangeDN", new LdapAttributeContext("legacyExchangeDN","1.2.840.113556.1.4.655",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "linkID", new LdapAttributeContext("linkID","1.2.840.113556.1.2.50",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "linkTrackSecret", new LdapAttributeContext("linkTrackSecret","1.2.840.113556.1.4.269",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "lmPwdHistory", new LdapAttributeContext("lmPwdHistory","1.2.840.113556.1.4.160",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "localeID", new LdapAttributeContext("localeID","1.2.840.113556.1.4.58",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "localizationDisplayId", new LdapAttributeContext("localizationDisplayId","1.2.840.113556.1.4.1353",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "localizedDescription", new LdapAttributeContext("localizedDescription","1.2.840.113556.1.4.817",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "localPolicyFlags", new LdapAttributeContext("localPolicyFlags","1.2.840.113556.1.4.56",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "localPolicyReference", new LdapAttributeContext("localPolicyReference","1.2.840.113556.1.4.457",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "location", new LdapAttributeContext("location","1.2.840.113556.1.4.222",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "lockoutDuration", new LdapAttributeContext("lockoutDuration","1.2.840.113556.1.4.60",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lockOutObservationWindow", new LdapAttributeContext("lockOutObservationWindow","1.2.840.113556.1.4.61",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lockoutThreshold", new LdapAttributeContext("lockoutThreshold","1.2.840.113556.1.4.73",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "lockoutTime", new LdapAttributeContext("lockoutTime","1.2.840.113556.1.4.662",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "loginShell", new LdapAttributeContext("loginShell","1.3.6.1.1.1.1.4",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "logonCount", new LdapAttributeContext("logonCount","1.2.840.113556.1.4.169",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "logonHours", new LdapAttributeContext("logonHours","1.2.840.113556.1.4.64",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "logonWorkstation", new LdapAttributeContext("logonWorkstation","1.2.840.113556.1.4.65",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "lSACreationTime", new LdapAttributeContext("lSACreationTime","1.2.840.113556.1.4.66",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "lSAModifiedCount", new LdapAttributeContext("lSAModifiedCount","1.2.840.113556.1.4.67",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "macAddress", new LdapAttributeContext("macAddress","1.3.6.1.1.1.1.22",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "machineArchitecture", new LdapAttributeContext("machineArchitecture","1.2.840.113556.1.4.68",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "machinePasswordChangeInterval", new LdapAttributeContext("machinePasswordChangeInterval","1.2.840.113556.1.4.520",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "machineRole", new LdapAttributeContext("machineRole","1.2.840.113556.1.4.71",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "machineWidePolicy", new LdapAttributeContext("machineWidePolicy","1.2.840.113556.1.4.459",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mail", new LdapAttributeContext("mail","0.9.2342.19200300.100.1.3",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mailAddress", new LdapAttributeContext("mailAddress","1.2.840.113556.1.4.786",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "managedBy", new LdapAttributeContext("managedBy","1.2.840.113556.1.4.653",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "managedObjects", new LdapAttributeContext("managedObjects","1.2.840.113556.1.4.654",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "manager", new LdapAttributeContext("manager","0.9.2342.19200300.100.1.10",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mAPIID", new LdapAttributeContext("mAPIID","1.2.840.113556.1.2.49",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "marshalledInterface", new LdapAttributeContext("marshalledInterface","1.2.840.113556.1.4.72",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "masteredBy", new LdapAttributeContext("masteredBy","1.2.840.113556.1.4.1409",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "maxPwdAge", new LdapAttributeContext("maxPwdAge","1.2.840.113556.1.4.74",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "maxRenewAge", new LdapAttributeContext("maxRenewAge","1.2.840.113556.1.4.75",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "maxStorage", new LdapAttributeContext("maxStorage","1.2.840.113556.1.4.76",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "maxTicketAge", new LdapAttributeContext("maxTicketAge","1.2.840.113556.1.4.77",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mayContain", new LdapAttributeContext("mayContain","1.2.840.113556.1.2.25",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "meetingAdvertiseScope", new LdapAttributeContext("meetingAdvertiseScope","1.2.840.113556.1.4.582",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingApplication", new LdapAttributeContext("meetingApplication","1.2.840.113556.1.4.573",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingBandwidth", new LdapAttributeContext("meetingBandwidth","1.2.840.113556.1.4.589",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "meetingBlob", new LdapAttributeContext("meetingBlob","1.2.840.113556.1.4.590",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "meetingContactInfo", new LdapAttributeContext("meetingContactInfo","1.2.840.113556.1.4.578",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingDescription", new LdapAttributeContext("meetingDescription","1.2.840.113556.1.4.567",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingEndTime", new LdapAttributeContext("meetingEndTime","1.2.840.113556.1.4.588",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "meetingID", new LdapAttributeContext("meetingID","1.2.840.113556.1.4.565",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingIP", new LdapAttributeContext("meetingIP","1.2.840.113556.1.4.580",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingIsEncrypted", new LdapAttributeContext("meetingIsEncrypted","1.2.840.113556.1.4.585",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingKeyword", new LdapAttributeContext("meetingKeyword","1.2.840.113556.1.4.568",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingLanguage", new LdapAttributeContext("meetingLanguage","1.2.840.113556.1.4.574",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingLocation", new LdapAttributeContext("meetingLocation","1.2.840.113556.1.4.569",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingMaxParticipants", new LdapAttributeContext("meetingMaxParticipants","1.2.840.113556.1.4.576",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "meetingName", new LdapAttributeContext("meetingName","1.2.840.113556.1.4.566",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingOriginator", new LdapAttributeContext("meetingOriginator","1.2.840.113556.1.4.577",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingOwner", new LdapAttributeContext("meetingOwner","1.2.840.113556.1.4.579",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingProtocol", new LdapAttributeContext("meetingProtocol","1.2.840.113556.1.4.570",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingRating", new LdapAttributeContext("meetingRating","1.2.840.113556.1.4.584",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingRecurrence", new LdapAttributeContext("meetingRecurrence","1.2.840.113556.1.4.586",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingScope", new LdapAttributeContext("meetingScope","1.2.840.113556.1.4.581",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingStartTime", new LdapAttributeContext("meetingStartTime","1.2.840.113556.1.4.587",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "meetingType", new LdapAttributeContext("meetingType","1.2.840.113556.1.4.571",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "meetingURL", new LdapAttributeContext("meetingURL","1.2.840.113556.1.4.583",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "member", new LdapAttributeContext("member","2.5.4.31",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "memberNisNetgroup", new LdapAttributeContext("memberNisNetgroup","1.3.6.1.1.1.1.13",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "memberOf", new LdapAttributeContext("memberOf","1.2.840.113556.1.2.102",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "memberUid", new LdapAttributeContext("memberUid","1.3.6.1.1.1.1.12",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "mhsORAddress", new LdapAttributeContext("mhsORAddress","1.2.840.113556.1.4.650",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "middleName", new LdapAttributeContext("middleName","2.16.840.1.113730.3.1.34",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "minPwdAge", new LdapAttributeContext("minPwdAge","1.2.840.113556.1.4.78",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "minPwdLength", new LdapAttributeContext("minPwdLength","1.2.840.113556.1.4.79",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "minTicketAge", new LdapAttributeContext("minTicketAge","1.2.840.113556.1.4.80",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mobile", new LdapAttributeContext("mobile","0.9.2342.19200300.100.1.41",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "modifiedCount", new LdapAttributeContext("modifiedCount","1.2.840.113556.1.4.168",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "modifiedCountAtLastProm", new LdapAttributeContext("modifiedCountAtLastProm","1.2.840.113556.1.4.81",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "modifyTimeStamp", new LdapAttributeContext("modifyTimeStamp","2.5.18.2",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "moniker", new LdapAttributeContext("moniker","1.2.840.113556.1.4.82",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "monikerDisplayName", new LdapAttributeContext("monikerDisplayName","1.2.840.113556.1.4.83",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "moveTreeState", new LdapAttributeContext("moveTreeState","1.2.840.113556.1.4.1305",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msAuthz-CentralAccessPolicyID", new LdapAttributeContext("msAuthz-CentralAccessPolicyID","1.2.840.113556.1.4.2154",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "msAuthz-EffectiveSecurityPolicy", new LdapAttributeContext("msAuthz-EffectiveSecurityPolicy","1.2.840.113556.1.4.2150",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msAuthz-LastEffectiveSecurityPolicy", new LdapAttributeContext("msAuthz-LastEffectiveSecurityPolicy","1.2.840.113556.1.4.2152",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msAuthz-MemberRulesInCentralAccessPolicy", new LdapAttributeContext("msAuthz-MemberRulesInCentralAccessPolicy","1.2.840.113556.1.4.2155",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msAuthz-MemberRulesInCentralAccessPolicyBL", new LdapAttributeContext("msAuthz-MemberRulesInCentralAccessPolicyBL","1.2.840.113556.1.4.2156",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msAuthz-ProposedSecurityPolicy", new LdapAttributeContext("msAuthz-ProposedSecurityPolicy","1.2.840.113556.1.4.2151",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msAuthz-ResourceCondition", new LdapAttributeContext("msAuthz-ResourceCondition","1.2.840.113556.1.4.2153",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msCOM-DefaultPartitionLink", new LdapAttributeContext("msCOM-DefaultPartitionLink","1.2.840.113556.1.4.1427",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msCOM-ObjectId", new LdapAttributeContext("msCOM-ObjectId","1.2.840.113556.1.4.1428",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msCOM-PartitionLink", new LdapAttributeContext("msCOM-PartitionLink","1.2.840.113556.1.4.1423",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msCOM-PartitionSetLink", new LdapAttributeContext("msCOM-PartitionSetLink","1.2.840.113556.1.4.1424",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msCOM-UserLink", new LdapAttributeContext("msCOM-UserLink","1.2.840.113556.1.4.1425",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msCOM-UserPartitionSetLink", new LdapAttributeContext("msCOM-UserPartitionSetLink","1.2.840.113556.1.4.1426",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mscopeId", new LdapAttributeContext("mscopeId","1.2.840.113556.1.4.716",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msDFS-Commentv2", new LdapAttributeContext("msDFS-Commentv2","1.2.840.113556.1.4.2036",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFS-GenerationGUIDv2", new LdapAttributeContext("msDFS-GenerationGUIDv2","1.2.840.113556.1.4.2032",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFS-LastModifiedv2", new LdapAttributeContext("msDFS-LastModifiedv2","1.2.840.113556.1.4.2034",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msDFS-LinkIdentityGUIDv2", new LdapAttributeContext("msDFS-LinkIdentityGUIDv2","1.2.840.113556.1.4.2041",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFS-LinkPathv2", new LdapAttributeContext("msDFS-LinkPathv2","1.2.840.113556.1.4.2039",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFS-LinkSecurityDescriptorv2", new LdapAttributeContext("msDFS-LinkSecurityDescriptorv2","1.2.840.113556.1.4.2040",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "msDFS-NamespaceIdentityGUIDv2", new LdapAttributeContext("msDFS-NamespaceIdentityGUIDv2","1.2.840.113556.1.4.2033",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFS-Propertiesv2", new LdapAttributeContext("msDFS-Propertiesv2","1.2.840.113556.1.4.2037",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-CachePolicy", new LdapAttributeContext("msDFSR-CachePolicy","1.2.840.113556.1.6.13.3.29",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-CommonStagingPath", new LdapAttributeContext("msDFSR-CommonStagingPath","1.2.840.113556.1.6.13.3.38",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-CommonStagingSizeInMb", new LdapAttributeContext("msDFSR-CommonStagingSizeInMb","1.2.840.113556.1.6.13.3.39",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-ComputerReference", new LdapAttributeContext("msDFSR-ComputerReference","1.2.840.113556.1.6.13.3.101",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDFSR-ComputerReferenceBL", new LdapAttributeContext("msDFSR-ComputerReferenceBL","1.2.840.113556.1.6.13.3.103",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDFSR-ConflictPath", new LdapAttributeContext("msDFSR-ConflictPath","1.2.840.113556.1.6.13.3.7",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-ConflictSizeInMb", new LdapAttributeContext("msDFSR-ConflictSizeInMb","1.2.840.113556.1.6.13.3.8",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-ContentSetGuid", new LdapAttributeContext("msDFSR-ContentSetGuid","1.2.840.113556.1.6.13.3.18",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFSR-DefaultCompressionExclusionFilter", new LdapAttributeContext("msDFSR-DefaultCompressionExclusionFilter","1.2.840.113556.1.6.13.3.34",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-DeletedPath", new LdapAttributeContext("msDFSR-DeletedPath","1.2.840.113556.1.6.13.3.26",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-DeletedSizeInMb", new LdapAttributeContext("msDFSR-DeletedSizeInMb","1.2.840.113556.1.6.13.3.27",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-DfsLinkTarget", new LdapAttributeContext("msDFSR-DfsLinkTarget","1.2.840.113556.1.6.13.3.24",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-DfsPath", new LdapAttributeContext("msDFSR-DfsPath","1.2.840.113556.1.6.13.3.21",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-DirectoryFilter", new LdapAttributeContext("msDFSR-DirectoryFilter","1.2.840.113556.1.6.13.3.13",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-DisablePacketPrivacy", new LdapAttributeContext("msDFSR-DisablePacketPrivacy","1.2.840.113556.1.6.13.3.32",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDFSR-Enabled", new LdapAttributeContext("msDFSR-Enabled","1.2.840.113556.1.6.13.3.9",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDFSR-Extension", new LdapAttributeContext("msDFSR-Extension","1.2.840.113556.1.6.13.3.2",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFSR-FileFilter", new LdapAttributeContext("msDFSR-FileFilter","1.2.840.113556.1.6.13.3.12",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-Flags", new LdapAttributeContext("msDFSR-Flags","1.2.840.113556.1.6.13.3.16",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-Keywords", new LdapAttributeContext("msDFSR-Keywords","1.2.840.113556.1.6.13.3.15",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-MaxAgeInCacheInMin", new LdapAttributeContext("msDFSR-MaxAgeInCacheInMin","1.2.840.113556.1.6.13.3.31",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-MemberReference", new LdapAttributeContext("msDFSR-MemberReference","1.2.840.113556.1.6.13.3.100",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDFSR-MemberReferenceBL", new LdapAttributeContext("msDFSR-MemberReferenceBL","1.2.840.113556.1.6.13.3.102",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDFSR-MinDurationCacheInMin", new LdapAttributeContext("msDFSR-MinDurationCacheInMin","1.2.840.113556.1.6.13.3.30",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-OnDemandExclusionDirectoryFilter", new LdapAttributeContext("msDFSR-OnDemandExclusionDirectoryFilter","1.2.840.113556.1.6.13.3.36",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-OnDemandExclusionFileFilter", new LdapAttributeContext("msDFSR-OnDemandExclusionFileFilter","1.2.840.113556.1.6.13.3.35",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-Options", new LdapAttributeContext("msDFSR-Options","1.2.840.113556.1.6.13.3.17",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-Options2", new LdapAttributeContext("msDFSR-Options2","1.2.840.113556.1.6.13.3.37",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-Priority", new LdapAttributeContext("msDFSR-Priority","1.2.840.113556.1.6.13.3.25",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-RdcEnabled", new LdapAttributeContext("msDFSR-RdcEnabled","1.2.840.113556.1.6.13.3.19",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDFSR-RdcMinFileSizeInKb", new LdapAttributeContext("msDFSR-RdcMinFileSizeInKb","1.2.840.113556.1.6.13.3.20",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-ReadOnly", new LdapAttributeContext("msDFSR-ReadOnly","1.2.840.113556.1.6.13.3.28",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDFSR-ReplicationGroupGuid", new LdapAttributeContext("msDFSR-ReplicationGroupGuid","1.2.840.113556.1.6.13.3.23",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFSR-ReplicationGroupType", new LdapAttributeContext("msDFSR-ReplicationGroupType","1.2.840.113556.1.6.13.3.10",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-RootFence", new LdapAttributeContext("msDFSR-RootFence","1.2.840.113556.1.6.13.3.22",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-RootPath", new LdapAttributeContext("msDFSR-RootPath","1.2.840.113556.1.6.13.3.3",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-RootSizeInMb", new LdapAttributeContext("msDFSR-RootSizeInMb","1.2.840.113556.1.6.13.3.4",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-Schedule", new LdapAttributeContext("msDFSR-Schedule","1.2.840.113556.1.6.13.3.14",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFSR-StagingCleanupTriggerInPercent", new LdapAttributeContext("msDFSR-StagingCleanupTriggerInPercent","1.2.840.113556.1.6.13.3.40",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-StagingPath", new LdapAttributeContext("msDFSR-StagingPath","1.2.840.113556.1.6.13.3.5",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFSR-StagingSizeInMb", new LdapAttributeContext("msDFSR-StagingSizeInMb","1.2.840.113556.1.6.13.3.6",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDFSR-TombstoneExpiryInMin", new LdapAttributeContext("msDFSR-TombstoneExpiryInMin","1.2.840.113556.1.6.13.3.11",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFSR-Version", new LdapAttributeContext("msDFSR-Version","1.2.840.113556.1.6.13.3.1",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFS-SchemaMajorVersion", new LdapAttributeContext("msDFS-SchemaMajorVersion","1.2.840.113556.1.4.2030",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFS-SchemaMinorVersion", new LdapAttributeContext("msDFS-SchemaMinorVersion","1.2.840.113556.1.4.2031",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDFS-ShortNameLinkPathv2", new LdapAttributeContext("msDFS-ShortNameLinkPathv2","1.2.840.113556.1.4.2042",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDFS-TargetListv2", new LdapAttributeContext("msDFS-TargetListv2","1.2.840.113556.1.4.2038",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDFS-Ttlv2", new LdapAttributeContext("msDFS-Ttlv2","1.2.840.113556.1.4.2035",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-DNSKEYRecords", new LdapAttributeContext("msDNS-DNSKEYRecords","1.2.840.113556.1.4.2145",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDNS-DNSKEYRecordSetTTL", new LdapAttributeContext("msDNS-DNSKEYRecordSetTTL","1.2.840.113556.1.4.2139",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-DSRecordAlgorithms", new LdapAttributeContext("msDNS-DSRecordAlgorithms","1.2.840.113556.1.4.2134",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-DSRecordSetTTL", new LdapAttributeContext("msDNS-DSRecordSetTTL","1.2.840.113556.1.4.2140",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-IsSigned", new LdapAttributeContext("msDNS-IsSigned","1.2.840.113556.1.4.2130",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDNS-KeymasterZones", new LdapAttributeContext("msDNS-KeymasterZones","1.2.840.113556.1.4.2128",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDNS-MaintainTrustAnchor", new LdapAttributeContext("msDNS-MaintainTrustAnchor","1.2.840.113556.1.4.2133",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-NSEC3CurrentSalt", new LdapAttributeContext("msDNS-NSEC3CurrentSalt","1.2.840.113556.1.4.2149",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDNS-NSEC3HashAlgorithm", new LdapAttributeContext("msDNS-NSEC3HashAlgorithm","1.2.840.113556.1.4.2136",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-NSEC3Iterations", new LdapAttributeContext("msDNS-NSEC3Iterations","1.2.840.113556.1.4.2138",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-NSEC3OptOut", new LdapAttributeContext("msDNS-NSEC3OptOut","1.2.840.113556.1.4.2132",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDNS-NSEC3RandomSaltLength", new LdapAttributeContext("msDNS-NSEC3RandomSaltLength","1.2.840.113556.1.4.2137",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-NSEC3UserSalt", new LdapAttributeContext("msDNS-NSEC3UserSalt","1.2.840.113556.1.4.2148",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDNS-ParentHasSecureDelegation", new LdapAttributeContext("msDNS-ParentHasSecureDelegation","1.2.840.113556.1.4.2146",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDNS-PropagationTime", new LdapAttributeContext("msDNS-PropagationTime","1.2.840.113556.1.4.2147",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-RFC5011KeyRollovers", new LdapAttributeContext("msDNS-RFC5011KeyRollovers","1.2.840.113556.1.4.2135",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDNS-SecureDelegationPollingPeriod", new LdapAttributeContext("msDNS-SecureDelegationPollingPeriod","1.2.840.113556.1.4.2142",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-SignatureInceptionOffset", new LdapAttributeContext("msDNS-SignatureInceptionOffset","1.2.840.113556.1.4.2141",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDNS-SigningKeyDescriptors", new LdapAttributeContext("msDNS-SigningKeyDescriptors","1.2.840.113556.1.4.2143",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDNS-SigningKeys", new LdapAttributeContext("msDNS-SigningKeys","1.2.840.113556.1.4.2144",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDNS-SignWithNSEC3", new LdapAttributeContext("msDNS-SignWithNSEC3","1.2.840.113556.1.4.2131",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDRM-IdentityCertificate", new LdapAttributeContext("msDRM-IdentityCertificate","1.2.840.113556.1.4.1843",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-AdditionalDnsHostName", new LdapAttributeContext("msDS-AdditionalDnsHostName","1.2.840.113556.1.4.1717",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AdditionalSamAccountName", new LdapAttributeContext("msDS-AdditionalSamAccountName","1.2.840.113556.1.4.1718",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AllowedDNSSuffixes", new LdapAttributeContext("msDS-AllowedDNSSuffixes","1.2.840.113556.1.4.1710",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AllowedToActOnBehalfOfOtherIdentity", new LdapAttributeContext("msDS-AllowedToActOnBehalfOfOtherIdentity","1.2.840.113556.1.4.2182",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "msDS-AllowedToDelegateTo", new LdapAttributeContext("msDS-AllowedToDelegateTo","1.2.840.113556.1.4.1787",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AllUsersTrustQuota", new LdapAttributeContext("msDS-AllUsersTrustQuota","1.2.840.113556.1.4.1789",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AppliesToResourceTypes", new LdapAttributeContext("msDS-AppliesToResourceTypes","1.2.840.113556.1.4.2195",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-Approx-Immed-Subordinates", new LdapAttributeContext("msDS-Approx-Immed-Subordinates","1.2.840.113556.1.4.1669",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AuthenticatedAtDC", new LdapAttributeContext("msDS-AuthenticatedAtDC","1.2.840.113556.1.4.1958",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-AuthenticatedToAccountlist", new LdapAttributeContext("msDS-AuthenticatedToAccountlist","1.2.840.113556.1.4.1957",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-Auxiliary-Classes", new LdapAttributeContext("msDS-Auxiliary-Classes","1.2.840.113556.1.4.1458",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "msDS-AzApplicationData", new LdapAttributeContext("msDS-AzApplicationData","1.2.840.113556.1.4.1819",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzApplicationName", new LdapAttributeContext("msDS-AzApplicationName","1.2.840.113556.1.4.1798",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzApplicationVersion", new LdapAttributeContext("msDS-AzApplicationVersion","1.2.840.113556.1.4.1817",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzBizRule", new LdapAttributeContext("msDS-AzBizRule","1.2.840.113556.1.4.1801",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzBizRuleLanguage", new LdapAttributeContext("msDS-AzBizRuleLanguage","1.2.840.113556.1.4.1802",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzClassId", new LdapAttributeContext("msDS-AzClassId","1.2.840.113556.1.4.1816",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzDomainTimeout", new LdapAttributeContext("msDS-AzDomainTimeout","1.2.840.113556.1.4.1795",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzGenerateAudits", new LdapAttributeContext("msDS-AzGenerateAudits","1.2.840.113556.1.4.1805",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-AzGenericData", new LdapAttributeContext("msDS-AzGenericData","1.2.840.113556.1.4.1950",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzLastImportedBizRulePath", new LdapAttributeContext("msDS-AzLastImportedBizRulePath","1.2.840.113556.1.4.1803",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzLDAPQuery", new LdapAttributeContext("msDS-AzLDAPQuery","1.2.840.113556.1.4.1792",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzMajorVersion", new LdapAttributeContext("msDS-AzMajorVersion","1.2.840.113556.1.4.1824",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzMinorVersion", new LdapAttributeContext("msDS-AzMinorVersion","1.2.840.113556.1.4.1825",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzObjectGuid", new LdapAttributeContext("msDS-AzObjectGuid","1.2.840.113556.1.4.1949",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-AzOperationID", new LdapAttributeContext("msDS-AzOperationID","1.2.840.113556.1.4.1800",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzScopeName", new LdapAttributeContext("msDS-AzScopeName","1.2.840.113556.1.4.1799",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-AzScriptEngineCacheMax", new LdapAttributeContext("msDS-AzScriptEngineCacheMax","1.2.840.113556.1.4.1796",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzScriptTimeout", new LdapAttributeContext("msDS-AzScriptTimeout","1.2.840.113556.1.4.1797",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-AzTaskIsRoleDefinition", new LdapAttributeContext("msDS-AzTaskIsRoleDefinition","1.2.840.113556.1.4.1818",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-Behavior-Version", new LdapAttributeContext("msDS-Behavior-Version","1.2.840.113556.1.4.1459",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-BridgeHeadServersUsed", new LdapAttributeContext("msDS-BridgeHeadServersUsed","1.2.840.113556.1.4.2049",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msDS-ByteArray", new LdapAttributeContext("msDS-ByteArray","1.2.840.113556.1.4.1831",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-Cached-Membership", new LdapAttributeContext("msDS-Cached-Membership","1.2.840.113556.1.4.1441",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-Cached-Membership-Time-Stamp", new LdapAttributeContext("msDS-Cached-Membership-Time-Stamp","1.2.840.113556.1.4.1442",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-ClaimAttributeSource", new LdapAttributeContext("msDS-ClaimAttributeSource","1.2.840.113556.1.4.2099",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ClaimIsSingleValued", new LdapAttributeContext("msDS-ClaimIsSingleValued","1.2.840.113556.1.4.2160",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-ClaimIsValueSpaceRestricted", new LdapAttributeContext("msDS-ClaimIsValueSpaceRestricted","1.2.840.113556.1.4.2159",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-ClaimPossibleValues", new LdapAttributeContext("msDS-ClaimPossibleValues","1.2.840.113556.1.4.2097",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ClaimSharesPossibleValuesWith", new LdapAttributeContext("msDS-ClaimSharesPossibleValuesWith","1.2.840.113556.1.4.2101",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ClaimSharesPossibleValuesWithBL", new LdapAttributeContext("msDS-ClaimSharesPossibleValuesWithBL","1.2.840.113556.1.4.2102",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ClaimSource", new LdapAttributeContext("msDS-ClaimSource","1.2.840.113556.1.4.2157",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ClaimSourceType", new LdapAttributeContext("msDS-ClaimSourceType","1.2.840.113556.1.4.2158",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ClaimTypeAppliesToClass", new LdapAttributeContext("msDS-ClaimTypeAppliesToClass","1.2.840.113556.1.4.2100",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ClaimValueType", new LdapAttributeContext("msDS-ClaimValueType","1.2.840.113556.1.4.2098",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mS-DS-ConsistencyChildCount", new LdapAttributeContext("mS-DS-ConsistencyChildCount","1.2.840.113556.1.4.1361",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mS-DS-ConsistencyGuid", new LdapAttributeContext("mS-DS-ConsistencyGuid","1.2.840.113556.1.4.1360",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mS-DS-CreatorSID", new LdapAttributeContext("mS-DS-CreatorSID","1.2.840.113556.1.4.1410",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "msDS-DateTime", new LdapAttributeContext("msDS-DateTime","1.2.840.113556.1.4.1832",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msDS-DefaultQuota", new LdapAttributeContext("msDS-DefaultQuota","1.2.840.113556.1.4.1846",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-DeletedObjectLifetime", new LdapAttributeContext("msDS-DeletedObjectLifetime","1.2.840.113556.1.4.2068",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-DisableForInstances", new LdapAttributeContext("msDS-DisableForInstances","1.2.840.113556.1.4.1870",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-DisableForInstancesBL", new LdapAttributeContext("msDS-DisableForInstancesBL","1.2.840.113556.1.4.1871",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-DnsRootAlias", new LdapAttributeContext("msDS-DnsRootAlias","1.2.840.113556.1.4.1719",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-EgressClaimsTransformationPolicy", new LdapAttributeContext("msDS-EgressClaimsTransformationPolicy","1.2.840.113556.1.4.2192",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-EnabledFeature", new LdapAttributeContext("msDS-EnabledFeature","1.2.840.113556.1.4.2061",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-EnabledFeatureBL", new LdapAttributeContext("msDS-EnabledFeatureBL","1.2.840.113556.1.4.2069",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-Entry-Time-To-Die", new LdapAttributeContext("msDS-Entry-Time-To-Die","1.2.840.113556.1.4.1622",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msDS-ExecuteScriptPassword", new LdapAttributeContext("msDS-ExecuteScriptPassword","1.2.840.113556.1.4.1783",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-ExternalKey", new LdapAttributeContext("msDS-ExternalKey","1.2.840.113556.1.4.1833",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ExternalStore", new LdapAttributeContext("msDS-ExternalStore","1.2.840.113556.1.4.1834",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-FailedInteractiveLogonCount", new LdapAttributeContext("msDS-FailedInteractiveLogonCount","1.2.840.113556.1.4.1972",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon", new LdapAttributeContext("msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon","1.2.840.113556.1.4.1973",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-FilterContainers", new LdapAttributeContext("msDS-FilterContainers","1.2.840.113556.1.4.1703",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-GenerationId", new LdapAttributeContext("msDS-GenerationId","1.2.840.113556.1.4.2166",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-GeoCoordinatesAltitude", new LdapAttributeContext("msDS-GeoCoordinatesAltitude","1.2.840.113556.1.4.2183",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-GeoCoordinatesLatitude", new LdapAttributeContext("msDS-GeoCoordinatesLatitude","1.2.840.113556.1.4.2184",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-GeoCoordinatesLongitude", new LdapAttributeContext("msDS-GeoCoordinatesLongitude","1.2.840.113556.1.4.2185",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-GroupMSAMembership", new LdapAttributeContext("msDS-GroupMSAMembership","1.2.840.113556.1.4.2200",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "msDS-HABSeniorityIndex", new LdapAttributeContext("msDS-HABSeniorityIndex","1.2.840.113556.1.4.1997",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-HasDomainNCs", new LdapAttributeContext("msDS-HasDomainNCs","1.2.840.113556.1.4.1820",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-hasFullReplicaNCs", new LdapAttributeContext("msDS-hasFullReplicaNCs","1.2.840.113556.1.4.1925",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-HasInstantiatedNCs", new LdapAttributeContext("msDS-HasInstantiatedNCs","1.2.840.113556.1.4.1709",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msDS-hasMasterNCs", new LdapAttributeContext("msDS-hasMasterNCs","1.2.840.113556.1.4.1836",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-HostServiceAccount", new LdapAttributeContext("msDS-HostServiceAccount","1.2.840.113556.1.4.2056",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-HostServiceAccountBL", new LdapAttributeContext("msDS-HostServiceAccountBL","1.2.840.113556.1.4.2057",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-IngressClaimsTransformationPolicy", new LdapAttributeContext("msDS-IngressClaimsTransformationPolicy","1.2.840.113556.1.4.2191",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-Integer", new LdapAttributeContext("msDS-Integer","1.2.840.113556.1.4.1835",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-IntId", new LdapAttributeContext("msDS-IntId","1.2.840.113556.1.4.1716",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-IsDomainFor", new LdapAttributeContext("msDS-IsDomainFor","1.2.840.113556.1.4.1933",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-IsFullReplicaFor", new LdapAttributeContext("msDS-IsFullReplicaFor","1.2.840.113556.1.4.1932",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-isGC", new LdapAttributeContext("msDS-isGC","1.2.840.113556.1.4.1959",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-IsPartialReplicaFor", new LdapAttributeContext("msDS-IsPartialReplicaFor","1.2.840.113556.1.4.1934",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-IsPossibleValuesPresent", new LdapAttributeContext("msDS-IsPossibleValuesPresent","1.2.840.113556.1.4.2186",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-IsPrimaryComputerFor", new LdapAttributeContext("msDS-IsPrimaryComputerFor","1.2.840.113556.1.4.2168",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-isRODC", new LdapAttributeContext("msDS-isRODC","1.2.840.113556.1.4.1960",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-IsUsedAsResourceSecurityAttribute", new LdapAttributeContext("msDS-IsUsedAsResourceSecurityAttribute","1.2.840.113556.1.4.2095",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-IsUserCachableAtRodc", new LdapAttributeContext("msDS-IsUserCachableAtRodc","1.2.840.113556.1.4.2025",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-KeyVersionNumber", new LdapAttributeContext("msDS-KeyVersionNumber","1.2.840.113556.1.4.1782",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-KrbTgtLink", new LdapAttributeContext("msDS-KrbTgtLink","1.2.840.113556.1.4.1923",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-KrbTgtLinkBl", new LdapAttributeContext("msDS-KrbTgtLinkBl","1.2.840.113556.1.4.1931",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-LastFailedInteractiveLogonTime", new LdapAttributeContext("msDS-LastFailedInteractiveLogonTime","1.2.840.113556.1.4.1971",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-LastKnownRDN", new LdapAttributeContext("msDS-LastKnownRDN","1.2.840.113556.1.4.2067",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-LastSuccessfulInteractiveLogonTime", new LdapAttributeContext("msDS-LastSuccessfulInteractiveLogonTime","1.2.840.113556.1.4.1970",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-LocalEffectiveDeletionTime", new LdapAttributeContext("msDS-LocalEffectiveDeletionTime","1.2.840.113556.1.4.2059",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msDS-LocalEffectiveRecycleTime", new LdapAttributeContext("msDS-LocalEffectiveRecycleTime","1.2.840.113556.1.4.2060",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msDS-LockoutDuration", new LdapAttributeContext("msDS-LockoutDuration","1.2.840.113556.1.4.2018",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-LockoutObservationWindow", new LdapAttributeContext("msDS-LockoutObservationWindow","1.2.840.113556.1.4.2017",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-LockoutThreshold", new LdapAttributeContext("msDS-LockoutThreshold","1.2.840.113556.1.4.2019",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-LogonTimeSyncInterval", new LdapAttributeContext("msDS-LogonTimeSyncInterval","1.2.840.113556.1.4.1784",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ms-DS-MachineAccountQuota", new LdapAttributeContext("ms-DS-MachineAccountQuota","1.2.840.113556.1.4.1411",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ManagedPassword", new LdapAttributeContext("msDS-ManagedPassword","1.2.840.113556.1.4.2196",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-ManagedPasswordId", new LdapAttributeContext("msDS-ManagedPasswordId","1.2.840.113556.1.4.2197",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-ManagedPasswordInterval", new LdapAttributeContext("msDS-ManagedPasswordInterval","1.2.840.113556.1.4.2199",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ManagedPasswordPreviousId", new LdapAttributeContext("msDS-ManagedPasswordPreviousId","1.2.840.113556.1.4.2198",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDs-masteredBy", new LdapAttributeContext("msDs-masteredBy","1.2.840.113556.1.4.1837",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-MaximumPasswordAge", new LdapAttributeContext("msDS-MaximumPasswordAge","1.2.840.113556.1.4.2011",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDs-MaxValues", new LdapAttributeContext("msDs-MaxValues","1.2.840.113556.1.4.1842",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-MembersForAzRole", new LdapAttributeContext("msDS-MembersForAzRole","1.2.840.113556.1.4.1806",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-MembersForAzRoleBL", new LdapAttributeContext("msDS-MembersForAzRoleBL","1.2.840.113556.1.4.1807",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-MembersOfResourcePropertyList", new LdapAttributeContext("msDS-MembersOfResourcePropertyList","1.2.840.113556.1.4.2103",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-MembersOfResourcePropertyListBL", new LdapAttributeContext("msDS-MembersOfResourcePropertyListBL","1.2.840.113556.1.4.2104",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-MinimumPasswordAge", new LdapAttributeContext("msDS-MinimumPasswordAge","1.2.840.113556.1.4.2012",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-MinimumPasswordLength", new LdapAttributeContext("msDS-MinimumPasswordLength","1.2.840.113556.1.4.2013",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-NCReplCursors", new LdapAttributeContext("msDS-NCReplCursors","1.2.840.113556.1.4.1704",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-NC-Replica-Locations", new LdapAttributeContext("msDS-NC-Replica-Locations","1.2.840.113556.1.4.1661",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-NCReplInboundNeighbors", new LdapAttributeContext("msDS-NCReplInboundNeighbors","1.2.840.113556.1.4.1705",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-NCReplOutboundNeighbors", new LdapAttributeContext("msDS-NCReplOutboundNeighbors","1.2.840.113556.1.4.1706",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-NC-RO-Replica-Locations", new LdapAttributeContext("msDS-NC-RO-Replica-Locations","1.2.840.113556.1.4.1967",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-NC-RO-Replica-Locations-BL", new LdapAttributeContext("msDS-NC-RO-Replica-Locations-BL","1.2.840.113556.1.4.1968",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-NcType", new LdapAttributeContext("msDS-NcType","1.2.840.113556.1.4.2024",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-NeverRevealGroup", new LdapAttributeContext("msDS-NeverRevealGroup","1.2.840.113556.1.4.1926",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-NonMembers", new LdapAttributeContext("msDS-NonMembers","1.2.840.113556.1.4.1793",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-NonMembersBL", new LdapAttributeContext("msDS-NonMembersBL","1.2.840.113556.1.4.1794",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-Non-Security-Group-Extra-Classes", new LdapAttributeContext("msDS-Non-Security-Group-Extra-Classes","1.2.840.113556.1.4.1689",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ObjectReference", new LdapAttributeContext("msDS-ObjectReference","1.2.840.113556.1.4.1840",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ObjectReferenceBL", new LdapAttributeContext("msDS-ObjectReferenceBL","1.2.840.113556.1.4.1841",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OIDToGroupLink", new LdapAttributeContext("msDS-OIDToGroupLink","1.2.840.113556.1.4.2051",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OIDToGroupLinkBl", new LdapAttributeContext("msDS-OIDToGroupLinkBl","1.2.840.113556.1.4.2052",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OperationsForAzRole", new LdapAttributeContext("msDS-OperationsForAzRole","1.2.840.113556.1.4.1812",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OperationsForAzRoleBL", new LdapAttributeContext("msDS-OperationsForAzRoleBL","1.2.840.113556.1.4.1813",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OperationsForAzTask", new LdapAttributeContext("msDS-OperationsForAzTask","1.2.840.113556.1.4.1808",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OperationsForAzTaskBL", new LdapAttributeContext("msDS-OperationsForAzTaskBL","1.2.840.113556.1.4.1809",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-OptionalFeatureFlags", new LdapAttributeContext("msDS-OptionalFeatureFlags","1.2.840.113556.1.4.2063",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-OptionalFeatureGUID", new LdapAttributeContext("msDS-OptionalFeatureGUID","1.2.840.113556.1.4.2062",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-Other-Settings", new LdapAttributeContext("msDS-Other-Settings","1.2.840.113556.1.4.1621",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PasswordComplexityEnabled", new LdapAttributeContext("msDS-PasswordComplexityEnabled","1.2.840.113556.1.4.2015",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-PasswordHistoryLength", new LdapAttributeContext("msDS-PasswordHistoryLength","1.2.840.113556.1.4.2014",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-PasswordReversibleEncryptionEnabled", new LdapAttributeContext("msDS-PasswordReversibleEncryptionEnabled","1.2.840.113556.1.4.2016",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-PasswordSettingsPrecedence", new LdapAttributeContext("msDS-PasswordSettingsPrecedence","1.2.840.113556.1.4.2023",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-PerUserTrustQuota", new LdapAttributeContext("msDS-PerUserTrustQuota","1.2.840.113556.1.4.1788",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-PerUserTrustTombstonesQuota", new LdapAttributeContext("msDS-PerUserTrustTombstonesQuota","1.2.840.113556.1.4.1790",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-PhoneticCompanyName", new LdapAttributeContext("msDS-PhoneticCompanyName","1.2.840.113556.1.4.1945",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PhoneticDepartment", new LdapAttributeContext("msDS-PhoneticDepartment","1.2.840.113556.1.4.1944",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PhoneticDisplayName", new LdapAttributeContext("msDS-PhoneticDisplayName","1.2.840.113556.1.4.1946",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PhoneticFirstName", new LdapAttributeContext("msDS-PhoneticFirstName","1.2.840.113556.1.4.1942",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PhoneticLastName", new LdapAttributeContext("msDS-PhoneticLastName","1.2.840.113556.1.4.1943",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PortLDAP", new LdapAttributeContext("msDS-PortLDAP","1.2.840.113556.1.4.1859",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-PortSSL", new LdapAttributeContext("msDS-PortSSL","1.2.840.113556.1.4.1860",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-Preferred-GC-Site", new LdapAttributeContext("msDS-Preferred-GC-Site","1.2.840.113556.1.4.1444",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-PrimaryComputer", new LdapAttributeContext("msDS-PrimaryComputer","1.2.840.113556.1.4.2167",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-PrincipalName", new LdapAttributeContext("msDS-PrincipalName","1.2.840.113556.1.4.1865",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PromotionSettings", new LdapAttributeContext("msDS-PromotionSettings","1.2.840.113556.1.4.1962",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-PSOApplied", new LdapAttributeContext("msDS-PSOApplied","1.2.840.113556.1.4.2021",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-PSOAppliesTo", new LdapAttributeContext("msDS-PSOAppliesTo","1.2.840.113556.1.4.2020",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-QuotaAmount", new LdapAttributeContext("msDS-QuotaAmount","1.2.840.113556.1.4.1845",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-QuotaEffective", new LdapAttributeContext("msDS-QuotaEffective","1.2.840.113556.1.4.1848",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-QuotaTrustee", new LdapAttributeContext("msDS-QuotaTrustee","1.2.840.113556.1.4.1844",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "msDS-QuotaUsed", new LdapAttributeContext("msDS-QuotaUsed","1.2.840.113556.1.4.1849",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ReplAttributeMetaData", new LdapAttributeContext("msDS-ReplAttributeMetaData","1.2.840.113556.1.4.1707",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-ReplAuthenticationMode", new LdapAttributeContext("msDS-ReplAuthenticationMode","1.2.840.113556.1.4.1861",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mS-DS-ReplicatesNCReason", new LdapAttributeContext("mS-DS-ReplicatesNCReason","1.2.840.113556.1.4.1408",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msDS-ReplicationEpoch", new LdapAttributeContext("msDS-ReplicationEpoch","1.2.840.113556.1.4.1720",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-Replication-Notify-First-DSA-Delay", new LdapAttributeContext("msDS-Replication-Notify-First-DSA-Delay","1.2.840.113556.1.4.1663",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-Replication-Notify-Subsequent-DSA-Delay", new LdapAttributeContext("msDS-Replication-Notify-Subsequent-DSA-Delay","1.2.840.113556.1.4.1664",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ReplValueMetaData", new LdapAttributeContext("msDS-ReplValueMetaData","1.2.840.113556.1.4.1708",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-RequiredDomainBehaviorVersion", new LdapAttributeContext("msDS-RequiredDomainBehaviorVersion","1.2.840.113556.1.4.2066",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-RequiredForestBehaviorVersion", new LdapAttributeContext("msDS-RequiredForestBehaviorVersion","1.2.840.113556.1.4.2079",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ResultantPSO", new LdapAttributeContext("msDS-ResultantPSO","1.2.840.113556.1.4.2022",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-RetiredReplNCSignatures", new LdapAttributeContext("msDS-RetiredReplNCSignatures","1.2.840.113556.1.4.1826",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-RevealedDSAs", new LdapAttributeContext("msDS-RevealedDSAs","1.2.840.113556.1.4.1930",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-RevealedList", new LdapAttributeContext("msDS-RevealedList","1.2.840.113556.1.4.1940",LdapTokenFormat.StringObjectAccessPoint,"2.5.5.14",LdapAttributeSyntaxADSType.Undefined,LdapAttributeSyntaxSDSType.Undefined,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Object_Access_Point,"Object(Access-Point) syntax.") },
			{ "msDS-RevealedListBL", new LdapAttributeContext("msDS-RevealedListBL","1.2.840.113556.1.4.1975",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-RevealedUsers", new LdapAttributeContext("msDS-RevealedUsers","1.2.840.113556.1.4.1924",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msDS-RevealOnDemandGroup", new LdapAttributeContext("msDS-RevealOnDemandGroup","1.2.840.113556.1.4.1928",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDs-Schema-Extensions", new LdapAttributeContext("msDs-Schema-Extensions","1.2.840.113556.1.4.1440",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-SCPContainer", new LdapAttributeContext("msDS-SCPContainer","1.2.840.113556.1.4.1872",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-SDReferenceDomain", new LdapAttributeContext("msDS-SDReferenceDomain","1.2.840.113556.1.4.1711",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-SecondaryKrbTgtNumber", new LdapAttributeContext("msDS-SecondaryKrbTgtNumber","1.2.840.113556.1.4.1929",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-Security-Group-Extra-Classes", new LdapAttributeContext("msDS-Security-Group-Extra-Classes","1.2.840.113556.1.4.1688",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-SeniorityIndex", new LdapAttributeContext("msDS-SeniorityIndex","1.2.840.113556.1.4.1947",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-ServiceAccount", new LdapAttributeContext("msDS-ServiceAccount","1.2.840.113556.1.4.1866",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ServiceAccountBL", new LdapAttributeContext("msDS-ServiceAccountBL","1.2.840.113556.1.4.1867",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ServiceAccountDNSDomain", new LdapAttributeContext("msDS-ServiceAccountDNSDomain","1.2.840.113556.1.4.1862",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-Settings", new LdapAttributeContext("msDS-Settings","1.2.840.113556.1.4.1697",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-Site-Affinity", new LdapAttributeContext("msDS-Site-Affinity","1.2.840.113556.1.4.1443",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-SiteName", new LdapAttributeContext("msDS-SiteName","1.2.840.113556.1.4.1961",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-SourceObjectDN", new LdapAttributeContext("msDS-SourceObjectDN","1.2.840.113556.1.4.1879",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-SPNSuffixes", new LdapAttributeContext("msDS-SPNSuffixes","1.2.840.113556.1.4.1715",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-SupportedEncryptionTypes", new LdapAttributeContext("msDS-SupportedEncryptionTypes","1.2.840.113556.1.4.1963",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-TasksForAzRole", new LdapAttributeContext("msDS-TasksForAzRole","1.2.840.113556.1.4.1814",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TasksForAzRoleBL", new LdapAttributeContext("msDS-TasksForAzRoleBL","1.2.840.113556.1.4.1815",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TasksForAzTask", new LdapAttributeContext("msDS-TasksForAzTask","1.2.840.113556.1.4.1810",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TasksForAzTaskBL", new LdapAttributeContext("msDS-TasksForAzTaskBL","1.2.840.113556.1.4.1811",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TDOEgressBL", new LdapAttributeContext("msDS-TDOEgressBL","1.2.840.113556.1.4.2194",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TDOIngressBL", new LdapAttributeContext("msDS-TDOIngressBL","1.2.840.113556.1.4.2193",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-TombstoneQuotaFactor", new LdapAttributeContext("msDS-TombstoneQuotaFactor","1.2.840.113556.1.4.1847",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-TopQuotaUsage", new LdapAttributeContext("msDS-TopQuotaUsage","1.2.840.113556.1.4.1850",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-TransformationRules", new LdapAttributeContext("msDS-TransformationRules","1.2.840.113556.1.4.2189",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msDS-TransformationRulesCompiled", new LdapAttributeContext("msDS-TransformationRulesCompiled","1.2.840.113556.1.4.2190",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-TrustForestTrustInfo", new LdapAttributeContext("msDS-TrustForestTrustInfo","1.2.840.113556.1.4.1702",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msDS-UpdateScript", new LdapAttributeContext("msDS-UpdateScript","1.2.840.113556.1.4.1721",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ms-DS-UserAccountAutoLocked", new LdapAttributeContext("ms-DS-UserAccountAutoLocked","1.2.840.113556.1.4.1857",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-User-Account-Control-Computed", new LdapAttributeContext("msDS-User-Account-Control-Computed","1.2.840.113556.1.4.1460",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msDS-UserAccountDisabled", new LdapAttributeContext("msDS-UserAccountDisabled","1.2.840.113556.1.4.1853",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-UserDontExpirePassword", new LdapAttributeContext("msDS-UserDontExpirePassword","1.2.840.113556.1.4.1855",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "ms-DS-UserEncryptedTextPasswordAllowed", new LdapAttributeContext("ms-DS-UserEncryptedTextPasswordAllowed","1.2.840.113556.1.4.1856",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-UserPasswordExpired", new LdapAttributeContext("msDS-UserPasswordExpired","1.2.840.113556.1.4.1858",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-UserPasswordExpiryTimeComputed", new LdapAttributeContext("msDS-UserPasswordExpiryTimeComputed","1.2.840.113556.1.4.1996",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "ms-DS-UserPasswordNotRequired", new LdapAttributeContext("ms-DS-UserPasswordNotRequired","1.2.840.113556.1.4.1854",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msDS-USNLastSyncSuccess", new LdapAttributeContext("msDS-USNLastSyncSuccess","1.2.840.113556.1.4.2055",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msDS-ValueTypeReference", new LdapAttributeContext("msDS-ValueTypeReference","1.2.840.113556.1.4.2187",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msDS-ValueTypeReferenceBL", new LdapAttributeContext("msDS-ValueTypeReferenceBL","1.2.840.113556.1.4.2188",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msExchAssistantName", new LdapAttributeContext("msExchAssistantName","1.2.840.113556.1.2.444",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msExchHouseIdentifier", new LdapAttributeContext("msExchHouseIdentifier","1.2.840.113556.1.2.596",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msExchLabeledURI", new LdapAttributeContext("msExchLabeledURI","1.2.840.113556.1.2.593",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msFRS-Hub-Member", new LdapAttributeContext("msFRS-Hub-Member","1.2.840.113556.1.4.1693",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msFRS-Topology-Pref", new LdapAttributeContext("msFRS-Topology-Pref","1.2.840.113556.1.4.1692",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msFVE-KeyPackage", new LdapAttributeContext("msFVE-KeyPackage","1.2.840.113556.1.4.1999",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msFVE-RecoveryGuid", new LdapAttributeContext("msFVE-RecoveryGuid","1.2.840.113556.1.4.1965",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msFVE-RecoveryPassword", new LdapAttributeContext("msFVE-RecoveryPassword","1.2.840.113556.1.4.1964",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msFVE-VolumeGuid", new LdapAttributeContext("msFVE-VolumeGuid","1.2.840.113556.1.4.1998",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msieee80211-Data", new LdapAttributeContext("msieee80211-Data","1.2.840.113556.1.4.1821",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msieee80211-DataType", new LdapAttributeContext("msieee80211-DataType","1.2.840.113556.1.4.1822",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msieee80211-ID", new LdapAttributeContext("msieee80211-ID","1.2.840.113556.1.4.1823",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msiFileList", new LdapAttributeContext("msiFileList","1.2.840.113556.1.4.671",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msIIS-FTPDir", new LdapAttributeContext("msIIS-FTPDir","1.2.840.113556.1.4.1786",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msIIS-FTPRoot", new LdapAttributeContext("msIIS-FTPRoot","1.2.840.113556.1.4.1785",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msImaging-HashAlgorithm", new LdapAttributeContext("msImaging-HashAlgorithm","1.2.840.113556.1.4.2181",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msImaging-PSPIdentifier", new LdapAttributeContext("msImaging-PSPIdentifier","1.2.840.113556.1.4.2053",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msImaging-PSPString", new LdapAttributeContext("msImaging-PSPString","1.2.840.113556.1.4.2054",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msImaging-ThumbprintHash", new LdapAttributeContext("msImaging-ThumbprintHash","1.2.840.113556.1.4.2180",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msiScript", new LdapAttributeContext("msiScript","1.2.840.113556.1.4.814",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msiScriptName", new LdapAttributeContext("msiScriptName","1.2.840.113556.1.4.845",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msiScriptPath", new LdapAttributeContext("msiScriptPath","1.2.840.113556.1.4.15",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msiScriptSize", new LdapAttributeContext("msiScriptSize","1.2.840.113556.1.4.846",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msKds-CreateTime", new LdapAttributeContext("msKds-CreateTime","1.2.840.113556.1.4.2179",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msKds-DomainID", new LdapAttributeContext("msKds-DomainID","1.2.840.113556.1.4.2177",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msKds-KDFAlgorithmID", new LdapAttributeContext("msKds-KDFAlgorithmID","1.2.840.113556.1.4.2169",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msKds-KDFParam", new LdapAttributeContext("msKds-KDFParam","1.2.840.113556.1.4.2170",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msKds-PrivateKeyLength", new LdapAttributeContext("msKds-PrivateKeyLength","1.2.840.113556.1.4.2174",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msKds-PublicKeyLength", new LdapAttributeContext("msKds-PublicKeyLength","1.2.840.113556.1.4.2173",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msKds-RootKeyData", new LdapAttributeContext("msKds-RootKeyData","1.2.840.113556.1.4.2175",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msKds-SecretAgreementAlgorithmID", new LdapAttributeContext("msKds-SecretAgreementAlgorithmID","1.2.840.113556.1.4.2171",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msKds-SecretAgreementParam", new LdapAttributeContext("msKds-SecretAgreementParam","1.2.840.113556.1.4.2172",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msKds-UseStartTime", new LdapAttributeContext("msKds-UseStartTime","1.2.840.113556.1.4.2178",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msKds-Version", new LdapAttributeContext("msKds-Version","1.2.840.113556.1.4.2176",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQAuthenticate", new LdapAttributeContext("mSMQAuthenticate","1.2.840.113556.1.4.923",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQBasePriority", new LdapAttributeContext("mSMQBasePriority","1.2.840.113556.1.4.920",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQComputerType", new LdapAttributeContext("mSMQComputerType","1.2.840.113556.1.4.933",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "mSMQComputerTypeEx", new LdapAttributeContext("mSMQComputerTypeEx","1.2.840.113556.1.4.1417",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQCost", new LdapAttributeContext("mSMQCost","1.2.840.113556.1.4.946",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQCSPName", new LdapAttributeContext("mSMQCSPName","1.2.840.113556.1.4.940",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "mSMQDependentClientService", new LdapAttributeContext("mSMQDependentClientService","1.2.840.113556.1.4.1239",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQDependentClientServices", new LdapAttributeContext("mSMQDependentClientServices","1.2.840.113556.1.4.1226",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQDigests", new LdapAttributeContext("mSMQDigests","1.2.840.113556.1.4.948",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQDigestsMig", new LdapAttributeContext("mSMQDigestsMig","1.2.840.113556.1.4.966",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQDsService", new LdapAttributeContext("mSMQDsService","1.2.840.113556.1.4.1238",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQDsServices", new LdapAttributeContext("mSMQDsServices","1.2.840.113556.1.4.1228",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQEncryptKey", new LdapAttributeContext("mSMQEncryptKey","1.2.840.113556.1.4.936",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQForeign", new LdapAttributeContext("mSMQForeign","1.2.840.113556.1.4.934",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQInRoutingServers", new LdapAttributeContext("mSMQInRoutingServers","1.2.840.113556.1.4.929",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQInterval1", new LdapAttributeContext("mSMQInterval1","1.2.840.113556.1.4.1308",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQInterval2", new LdapAttributeContext("mSMQInterval2","1.2.840.113556.1.4.1309",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQJournal", new LdapAttributeContext("mSMQJournal","1.2.840.113556.1.4.918",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQJournalQuota", new LdapAttributeContext("mSMQJournalQuota","1.2.840.113556.1.4.921",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQLabel", new LdapAttributeContext("mSMQLabel","1.2.840.113556.1.4.922",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "mSMQLabelEx", new LdapAttributeContext("mSMQLabelEx","1.2.840.113556.1.4.1415",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQLongLived", new LdapAttributeContext("mSMQLongLived","1.2.840.113556.1.4.941",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQMigrated", new LdapAttributeContext("mSMQMigrated","1.2.840.113556.1.4.952",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "MSMQ-MulticastAddress", new LdapAttributeContext("MSMQ-MulticastAddress","1.2.840.113556.1.4.1714",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQNameStyle", new LdapAttributeContext("mSMQNameStyle","1.2.840.113556.1.4.939",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQNt4Flags", new LdapAttributeContext("mSMQNt4Flags","1.2.840.113556.1.4.964",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQNt4Stub", new LdapAttributeContext("mSMQNt4Stub","1.2.840.113556.1.4.960",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQOSType", new LdapAttributeContext("mSMQOSType","1.2.840.113556.1.4.935",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQOutRoutingServers", new LdapAttributeContext("mSMQOutRoutingServers","1.2.840.113556.1.4.928",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQOwnerID", new LdapAttributeContext("mSMQOwnerID","1.2.840.113556.1.4.925",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQPrevSiteGates", new LdapAttributeContext("mSMQPrevSiteGates","1.2.840.113556.1.4.1225",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQPrivacyLevel", new LdapAttributeContext("mSMQPrivacyLevel","1.2.840.113556.1.4.924",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQQMID", new LdapAttributeContext("mSMQQMID","1.2.840.113556.1.4.951",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQQueueJournalQuota", new LdapAttributeContext("mSMQQueueJournalQuota","1.2.840.113556.1.4.963",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQQueueNameExt", new LdapAttributeContext("mSMQQueueNameExt","1.2.840.113556.1.4.1243",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQQueueQuota", new LdapAttributeContext("mSMQQueueQuota","1.2.840.113556.1.4.962",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQQueueType", new LdapAttributeContext("mSMQQueueType","1.2.840.113556.1.4.917",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQQuota", new LdapAttributeContext("mSMQQuota","1.2.840.113556.1.4.919",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msMQ-Recipient-FormatName", new LdapAttributeContext("msMQ-Recipient-FormatName","1.2.840.113556.1.4.1695",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQRoutingService", new LdapAttributeContext("mSMQRoutingService","1.2.840.113556.1.4.1237",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQRoutingServices", new LdapAttributeContext("mSMQRoutingServices","1.2.840.113556.1.4.1227",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "MSMQ-SecuredSource", new LdapAttributeContext("MSMQ-SecuredSource","1.2.840.113556.1.4.1713",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQServices", new LdapAttributeContext("mSMQServices","1.2.840.113556.1.4.950",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQServiceType", new LdapAttributeContext("mSMQServiceType","1.2.840.113556.1.4.930",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mSMQSignCertificates", new LdapAttributeContext("mSMQSignCertificates","1.2.840.113556.1.4.947",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQSignCertificatesMig", new LdapAttributeContext("mSMQSignCertificatesMig","1.2.840.113556.1.4.967",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQSignKey", new LdapAttributeContext("mSMQSignKey","1.2.840.113556.1.4.937",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQSite1", new LdapAttributeContext("mSMQSite1","1.2.840.113556.1.4.943",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQSite2", new LdapAttributeContext("mSMQSite2","1.2.840.113556.1.4.944",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQSiteForeign", new LdapAttributeContext("mSMQSiteForeign","1.2.840.113556.1.4.961",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQSiteGates", new LdapAttributeContext("mSMQSiteGates","1.2.840.113556.1.4.945",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQSiteGatesMig", new LdapAttributeContext("mSMQSiteGatesMig","1.2.840.113556.1.4.1310",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "mSMQSiteID", new LdapAttributeContext("mSMQSiteID","1.2.840.113556.1.4.953",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQSiteName", new LdapAttributeContext("mSMQSiteName","1.2.840.113556.1.4.965",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "mSMQSiteNameEx", new LdapAttributeContext("mSMQSiteNameEx","1.2.840.113556.1.4.1416",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mSMQSites", new LdapAttributeContext("mSMQSites","1.2.840.113556.1.4.927",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQTransactional", new LdapAttributeContext("mSMQTransactional","1.2.840.113556.1.4.926",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mSMQUserSid", new LdapAttributeContext("mSMQUserSid","1.2.840.113556.1.4.1337",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mSMQVersion", new LdapAttributeContext("mSMQVersion","1.2.840.113556.1.4.942",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ms-net-ieee-80211-GP-PolicyData", new LdapAttributeContext("ms-net-ieee-80211-GP-PolicyData","1.2.840.113556.1.4.1952",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ms-net-ieee-80211-GP-PolicyGUID", new LdapAttributeContext("ms-net-ieee-80211-GP-PolicyGUID","1.2.840.113556.1.4.1951",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ms-net-ieee-80211-GP-PolicyReserved", new LdapAttributeContext("ms-net-ieee-80211-GP-PolicyReserved","1.2.840.113556.1.4.1953",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "ms-net-ieee-8023-GP-PolicyData", new LdapAttributeContext("ms-net-ieee-8023-GP-PolicyData","1.2.840.113556.1.4.1955",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ms-net-ieee-8023-GP-PolicyGUID", new LdapAttributeContext("ms-net-ieee-8023-GP-PolicyGUID","1.2.840.113556.1.4.1954",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "ms-net-ieee-8023-GP-PolicyReserved", new LdapAttributeContext("ms-net-ieee-8023-GP-PolicyReserved","1.2.840.113556.1.4.1956",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msNPAllowDialin", new LdapAttributeContext("msNPAllowDialin","1.2.840.113556.1.4.1119",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msNPCalledStationID", new LdapAttributeContext("msNPCalledStationID","1.2.840.113556.1.4.1123",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msNPCallingStationID", new LdapAttributeContext("msNPCallingStationID","1.2.840.113556.1.4.1124",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msNPSavedCallingStationID", new LdapAttributeContext("msNPSavedCallingStationID","1.2.840.113556.1.4.1130",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msPKIAccountCredentials", new LdapAttributeContext("msPKIAccountCredentials","1.2.840.113556.1.4.1894",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msPKI-Certificate-Application-Policy", new LdapAttributeContext("msPKI-Certificate-Application-Policy","1.2.840.113556.1.4.1674",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Certificate-Name-Flag", new LdapAttributeContext("msPKI-Certificate-Name-Flag","1.2.840.113556.1.4.1432",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-Certificate-Policy", new LdapAttributeContext("msPKI-Certificate-Policy","1.2.840.113556.1.4.1439",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Cert-Template-OID", new LdapAttributeContext("msPKI-Cert-Template-OID","1.2.840.113556.1.4.1436",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-CredentialRoamingTokens", new LdapAttributeContext("msPKI-CredentialRoamingTokens","1.2.840.113556.1.4.2050",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msPKIDPAPIMasterKeys", new LdapAttributeContext("msPKIDPAPIMasterKeys","1.2.840.113556.1.4.1893",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "msPKI-Enrollment-Flag", new LdapAttributeContext("msPKI-Enrollment-Flag","1.2.840.113556.1.4.1430",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-Enrollment-Servers", new LdapAttributeContext("msPKI-Enrollment-Servers","1.2.840.113556.1.4.2076",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Minimal-Key-Size", new LdapAttributeContext("msPKI-Minimal-Key-Size","1.2.840.113556.1.4.1433",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-OID-Attribute", new LdapAttributeContext("msPKI-OID-Attribute","1.2.840.113556.1.4.1671",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-OID-CPS", new LdapAttributeContext("msPKI-OID-CPS","1.2.840.113556.1.4.1672",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-OIDLocalizedName", new LdapAttributeContext("msPKI-OIDLocalizedName","1.2.840.113556.1.4.1712",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-OID-User-Notice", new LdapAttributeContext("msPKI-OID-User-Notice","1.2.840.113556.1.4.1673",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Private-Key-Flag", new LdapAttributeContext("msPKI-Private-Key-Flag","1.2.840.113556.1.4.1431",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-RA-Application-Policies", new LdapAttributeContext("msPKI-RA-Application-Policies","1.2.840.113556.1.4.1675",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-RA-Policies", new LdapAttributeContext("msPKI-RA-Policies","1.2.840.113556.1.4.1438",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-RA-Signature", new LdapAttributeContext("msPKI-RA-Signature","1.2.840.113556.1.4.1429",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKIRoamingTimeStamp", new LdapAttributeContext("msPKIRoamingTimeStamp","1.2.840.113556.1.4.1892",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msPKI-Site-Name", new LdapAttributeContext("msPKI-Site-Name","1.2.840.113556.1.4.2077",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Supersede-Templates", new LdapAttributeContext("msPKI-Supersede-Templates","1.2.840.113556.1.4.1437",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msPKI-Template-Minor-Revision", new LdapAttributeContext("msPKI-Template-Minor-Revision","1.2.840.113556.1.4.1435",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msPKI-Template-Schema-Version", new LdapAttributeContext("msPKI-Template-Schema-Version","1.2.840.113556.1.4.1434",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msRADIUSCallbackNumber", new LdapAttributeContext("msRADIUSCallbackNumber","1.2.840.113556.1.4.1145",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUS-FramedInterfaceId", new LdapAttributeContext("msRADIUS-FramedInterfaceId","1.2.840.113556.1.4.1913",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUSFramedIPAddress", new LdapAttributeContext("msRADIUSFramedIPAddress","1.2.840.113556.1.4.1153",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msRADIUS-FramedIpv6Prefix", new LdapAttributeContext("msRADIUS-FramedIpv6Prefix","1.2.840.113556.1.4.1915",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUS-FramedIpv6Route", new LdapAttributeContext("msRADIUS-FramedIpv6Route","1.2.840.113556.1.4.1917",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUSFramedRoute", new LdapAttributeContext("msRADIUSFramedRoute","1.2.840.113556.1.4.1158",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUS-SavedFramedInterfaceId", new LdapAttributeContext("msRADIUS-SavedFramedInterfaceId","1.2.840.113556.1.4.1914",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUS-SavedFramedIpv6Prefix", new LdapAttributeContext("msRADIUS-SavedFramedIpv6Prefix","1.2.840.113556.1.4.1916",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUS-SavedFramedIpv6Route", new LdapAttributeContext("msRADIUS-SavedFramedIpv6Route","1.2.840.113556.1.4.1918",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRADIUSServiceType", new LdapAttributeContext("msRADIUSServiceType","1.2.840.113556.1.4.1171",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msRASSavedCallbackNumber", new LdapAttributeContext("msRASSavedCallbackNumber","1.2.840.113556.1.4.1189",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRASSavedFramedIPAddress", new LdapAttributeContext("msRASSavedFramedIPAddress","1.2.840.113556.1.4.1190",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msRASSavedFramedRoute", new LdapAttributeContext("msRASSavedFramedRoute","1.2.840.113556.1.4.1191",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msRRASAttribute", new LdapAttributeContext("msRRASAttribute","1.2.840.113556.1.4.884",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msRRASVendorAttributeEntry", new LdapAttributeContext("msRRASVendorAttributeEntry","1.2.840.113556.1.4.883",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30Aliases", new LdapAttributeContext("msSFU30Aliases","1.2.840.113556.1.6.18.1.323",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30CryptMethod", new LdapAttributeContext("msSFU30CryptMethod","1.2.840.113556.1.6.18.1.352",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30Domains", new LdapAttributeContext("msSFU30Domains","1.2.840.113556.1.6.18.1.340",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30FieldSeparator", new LdapAttributeContext("msSFU30FieldSeparator","1.2.840.113556.1.6.18.1.302",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30IntraFieldSeparator", new LdapAttributeContext("msSFU30IntraFieldSeparator","1.2.840.113556.1.6.18.1.303",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30IsValidContainer", new LdapAttributeContext("msSFU30IsValidContainer","1.2.840.113556.1.6.18.1.350",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msSFU30KeyAttributes", new LdapAttributeContext("msSFU30KeyAttributes","1.2.840.113556.1.6.18.1.301",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30KeyValues", new LdapAttributeContext("msSFU30KeyValues","1.2.840.113556.1.6.18.1.324",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30MapFilter", new LdapAttributeContext("msSFU30MapFilter","1.2.840.113556.1.6.18.1.306",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30MasterServerName", new LdapAttributeContext("msSFU30MasterServerName","1.2.840.113556.1.6.18.1.307",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30MaxGidNumber", new LdapAttributeContext("msSFU30MaxGidNumber","1.2.840.113556.1.6.18.1.342",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msSFU30MaxUidNumber", new LdapAttributeContext("msSFU30MaxUidNumber","1.2.840.113556.1.6.18.1.343",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msSFU30Name", new LdapAttributeContext("msSFU30Name","1.2.840.113556.1.6.18.1.309",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30NetgroupHostAtDomain", new LdapAttributeContext("msSFU30NetgroupHostAtDomain","1.2.840.113556.1.6.18.1.348",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30NetgroupUserAtDomain", new LdapAttributeContext("msSFU30NetgroupUserAtDomain","1.2.840.113556.1.6.18.1.349",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30NisDomain", new LdapAttributeContext("msSFU30NisDomain","1.2.840.113556.1.6.18.1.339",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30NSMAPFieldPosition", new LdapAttributeContext("msSFU30NSMAPFieldPosition","1.2.840.113556.1.6.18.1.345",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSFU30OrderNumber", new LdapAttributeContext("msSFU30OrderNumber","1.2.840.113556.1.6.18.1.308",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30PosixMember", new LdapAttributeContext("msSFU30PosixMember","1.2.840.113556.1.6.18.1.346",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msSFU30PosixMemberOf", new LdapAttributeContext("msSFU30PosixMemberOf","1.2.840.113556.1.6.18.1.347",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msSFU30ResultAttributes", new LdapAttributeContext("msSFU30ResultAttributes","1.2.840.113556.1.6.18.1.305",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30SearchAttributes", new LdapAttributeContext("msSFU30SearchAttributes","1.2.840.113556.1.6.18.1.304",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30SearchContainer", new LdapAttributeContext("msSFU30SearchContainer","1.2.840.113556.1.6.18.1.300",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSFU30YpServers", new LdapAttributeContext("msSFU30YpServers","1.2.840.113556.1.6.18.1.341",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "msSPP-ConfigLicense", new LdapAttributeContext("msSPP-ConfigLicense","1.2.840.113556.1.4.2087",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msSPP-ConfirmationId", new LdapAttributeContext("msSPP-ConfirmationId","1.2.840.113556.1.4.2084",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSPP-CSVLKPartialProductKey", new LdapAttributeContext("msSPP-CSVLKPartialProductKey","1.2.840.113556.1.4.2106",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSPP-CSVLKPid", new LdapAttributeContext("msSPP-CSVLKPid","1.2.840.113556.1.4.2105",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSPP-CSVLKSkuId", new LdapAttributeContext("msSPP-CSVLKSkuId","1.2.840.113556.1.4.2081",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msSPP-InstallationId", new LdapAttributeContext("msSPP-InstallationId","1.2.840.113556.1.4.2083",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msSPP-IssuanceLicense", new LdapAttributeContext("msSPP-IssuanceLicense","1.2.840.113556.1.4.2088",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msSPP-KMSIds", new LdapAttributeContext("msSPP-KMSIds","1.2.840.113556.1.4.2082",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msSPP-OnlineLicense", new LdapAttributeContext("msSPP-OnlineLicense","1.2.840.113556.1.4.2085",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msSPP-PhoneLicense", new LdapAttributeContext("msSPP-PhoneLicense","1.2.840.113556.1.4.2086",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "mS-SQL-Alias", new LdapAttributeContext("mS-SQL-Alias","1.2.840.113556.1.4.1395",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-AllowAnonymousSubscription", new LdapAttributeContext("mS-SQL-AllowAnonymousSubscription","1.2.840.113556.1.4.1394",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-AllowImmediateUpdatingSubscription", new LdapAttributeContext("mS-SQL-AllowImmediateUpdatingSubscription","1.2.840.113556.1.4.1404",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-AllowKnownPullSubscription", new LdapAttributeContext("mS-SQL-AllowKnownPullSubscription","1.2.840.113556.1.4.1403",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-AllowQueuedUpdatingSubscription", new LdapAttributeContext("mS-SQL-AllowQueuedUpdatingSubscription","1.2.840.113556.1.4.1405",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-AllowSnapshotFilesFTPDownloading", new LdapAttributeContext("mS-SQL-AllowSnapshotFilesFTPDownloading","1.2.840.113556.1.4.1406",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-AppleTalk", new LdapAttributeContext("mS-SQL-AppleTalk","1.2.840.113556.1.4.1378",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Applications", new LdapAttributeContext("mS-SQL-Applications","1.2.840.113556.1.4.1400",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Build", new LdapAttributeContext("mS-SQL-Build","1.2.840.113556.1.4.1368",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mS-SQL-CharacterSet", new LdapAttributeContext("mS-SQL-CharacterSet","1.2.840.113556.1.4.1370",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mS-SQL-Clustered", new LdapAttributeContext("mS-SQL-Clustered","1.2.840.113556.1.4.1373",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-ConnectionURL", new LdapAttributeContext("mS-SQL-ConnectionURL","1.2.840.113556.1.4.1383",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Contact", new LdapAttributeContext("mS-SQL-Contact","1.2.840.113556.1.4.1365",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-CreationDate", new LdapAttributeContext("mS-SQL-CreationDate","1.2.840.113556.1.4.1397",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Database", new LdapAttributeContext("mS-SQL-Database","1.2.840.113556.1.4.1393",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Description", new LdapAttributeContext("mS-SQL-Description","1.2.840.113556.1.4.1390",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-GPSHeight", new LdapAttributeContext("mS-SQL-GPSHeight","1.2.840.113556.1.4.1387",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-GPSLatitude", new LdapAttributeContext("mS-SQL-GPSLatitude","1.2.840.113556.1.4.1385",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-GPSLongitude", new LdapAttributeContext("mS-SQL-GPSLongitude","1.2.840.113556.1.4.1386",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-InformationDirectory", new LdapAttributeContext("mS-SQL-InformationDirectory","1.2.840.113556.1.4.1392",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-InformationURL", new LdapAttributeContext("mS-SQL-InformationURL","1.2.840.113556.1.4.1382",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Keywords", new LdapAttributeContext("mS-SQL-Keywords","1.2.840.113556.1.4.1401",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Language", new LdapAttributeContext("mS-SQL-Language","1.2.840.113556.1.4.1389",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-LastBackupDate", new LdapAttributeContext("mS-SQL-LastBackupDate","1.2.840.113556.1.4.1398",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-LastDiagnosticDate", new LdapAttributeContext("mS-SQL-LastDiagnosticDate","1.2.840.113556.1.4.1399",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-LastUpdatedDate", new LdapAttributeContext("mS-SQL-LastUpdatedDate","1.2.840.113556.1.4.1381",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Location", new LdapAttributeContext("mS-SQL-Location","1.2.840.113556.1.4.1366",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Memory", new LdapAttributeContext("mS-SQL-Memory","1.2.840.113556.1.4.1367",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mS-SQL-MultiProtocol", new LdapAttributeContext("mS-SQL-MultiProtocol","1.2.840.113556.1.4.1375",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Name", new LdapAttributeContext("mS-SQL-Name","1.2.840.113556.1.4.1363",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-NamedPipe", new LdapAttributeContext("mS-SQL-NamedPipe","1.2.840.113556.1.4.1374",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-PublicationURL", new LdapAttributeContext("mS-SQL-PublicationURL","1.2.840.113556.1.4.1384",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Publisher", new LdapAttributeContext("mS-SQL-Publisher","1.2.840.113556.1.4.1402",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-RegisteredOwner", new LdapAttributeContext("mS-SQL-RegisteredOwner","1.2.840.113556.1.4.1364",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-ServiceAccount", new LdapAttributeContext("mS-SQL-ServiceAccount","1.2.840.113556.1.4.1369",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Size", new LdapAttributeContext("mS-SQL-Size","1.2.840.113556.1.4.1396",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mS-SQL-SortOrder", new LdapAttributeContext("mS-SQL-SortOrder","1.2.840.113556.1.4.1371",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-SPX", new LdapAttributeContext("mS-SQL-SPX","1.2.840.113556.1.4.1376",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Status", new LdapAttributeContext("mS-SQL-Status","1.2.840.113556.1.4.1380",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "mS-SQL-TCPIP", new LdapAttributeContext("mS-SQL-TCPIP","1.2.840.113556.1.4.1377",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-ThirdParty", new LdapAttributeContext("mS-SQL-ThirdParty","1.2.840.113556.1.4.1407",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "mS-SQL-Type", new LdapAttributeContext("mS-SQL-Type","1.2.840.113556.1.4.1391",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-UnicodeSortOrder", new LdapAttributeContext("mS-SQL-UnicodeSortOrder","1.2.840.113556.1.4.1372",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "mS-SQL-Version", new LdapAttributeContext("mS-SQL-Version","1.2.840.113556.1.4.1388",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mS-SQL-Vines", new LdapAttributeContext("mS-SQL-Vines","1.2.840.113556.1.4.1379",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTAPI-ConferenceBlob", new LdapAttributeContext("msTAPI-ConferenceBlob","1.2.840.113556.1.4.1700",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msTAPI-IpAddress", new LdapAttributeContext("msTAPI-IpAddress","1.2.840.113556.1.4.1701",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTAPI-ProtocolId", new LdapAttributeContext("msTAPI-ProtocolId","1.2.840.113556.1.4.1699",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTAPI-uid", new LdapAttributeContext("msTAPI-uid","1.2.840.113556.1.4.1698",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTPM-OwnerInformation", new LdapAttributeContext("msTPM-OwnerInformation","1.2.840.113556.1.4.1966",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTPM-OwnerInformationTemp", new LdapAttributeContext("msTPM-OwnerInformationTemp","1.2.840.113556.1.4.2108",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTPM-SrkPubThumbprint", new LdapAttributeContext("msTPM-SrkPubThumbprint","1.2.840.113556.1.4.2107",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msTPM-TpmInformationForComputer", new LdapAttributeContext("msTPM-TpmInformationForComputer","1.2.840.113556.1.4.2109",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTPM-TpmInformationForComputerBL", new LdapAttributeContext("msTPM-TpmInformationForComputerBL","1.2.840.113556.1.4.2110",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTSAllowLogon", new LdapAttributeContext("msTSAllowLogon","1.2.840.113556.1.4.1979",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSBrokenConnectionAction", new LdapAttributeContext("msTSBrokenConnectionAction","1.2.840.113556.1.4.1985",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSConnectClientDrives", new LdapAttributeContext("msTSConnectClientDrives","1.2.840.113556.1.4.1986",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSConnectPrinterDrives", new LdapAttributeContext("msTSConnectPrinterDrives","1.2.840.113556.1.4.1987",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSDefaultToMainPrinter", new LdapAttributeContext("msTSDefaultToMainPrinter","1.2.840.113556.1.4.1988",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSEndpointData", new LdapAttributeContext("msTSEndpointData","1.2.840.113556.1.4.2070",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSEndpointPlugin", new LdapAttributeContext("msTSEndpointPlugin","1.2.840.113556.1.4.2072",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSEndpointType", new LdapAttributeContext("msTSEndpointType","1.2.840.113556.1.4.2071",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msTSExpireDate", new LdapAttributeContext("msTSExpireDate","1.2.840.113556.1.4.1993",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msTSExpireDate2", new LdapAttributeContext("msTSExpireDate2","1.2.840.113556.1.4.2000",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msTSExpireDate3", new LdapAttributeContext("msTSExpireDate3","1.2.840.113556.1.4.2003",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msTSExpireDate4", new LdapAttributeContext("msTSExpireDate4","1.2.840.113556.1.4.2006",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "msTSHomeDirectory", new LdapAttributeContext("msTSHomeDirectory","1.2.840.113556.1.4.1977",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSHomeDrive", new LdapAttributeContext("msTSHomeDrive","1.2.840.113556.1.4.1978",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSInitialProgram", new LdapAttributeContext("msTSInitialProgram","1.2.840.113556.1.4.1990",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLicenseVersion", new LdapAttributeContext("msTSLicenseVersion","1.2.840.113556.1.4.1994",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLicenseVersion2", new LdapAttributeContext("msTSLicenseVersion2","1.2.840.113556.1.4.2001",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLicenseVersion3", new LdapAttributeContext("msTSLicenseVersion3","1.2.840.113556.1.4.2004",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLicenseVersion4", new LdapAttributeContext("msTSLicenseVersion4","1.2.840.113556.1.4.2007",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLSProperty01", new LdapAttributeContext("msTSLSProperty01","1.2.840.113556.1.4.2009",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSLSProperty02", new LdapAttributeContext("msTSLSProperty02","1.2.840.113556.1.4.2010",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSManagingLS", new LdapAttributeContext("msTSManagingLS","1.2.840.113556.1.4.1995",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSManagingLS2", new LdapAttributeContext("msTSManagingLS2","1.2.840.113556.1.4.2002",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSManagingLS3", new LdapAttributeContext("msTSManagingLS3","1.2.840.113556.1.4.2005",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSManagingLS4", new LdapAttributeContext("msTSManagingLS4","1.2.840.113556.1.4.2008",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSMaxConnectionTime", new LdapAttributeContext("msTSMaxConnectionTime","1.2.840.113556.1.4.1982",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msTSMaxDisconnectionTime", new LdapAttributeContext("msTSMaxDisconnectionTime","1.2.840.113556.1.4.1981",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msTSMaxIdleTime", new LdapAttributeContext("msTSMaxIdleTime","1.2.840.113556.1.4.1983",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msTSPrimaryDesktop", new LdapAttributeContext("msTSPrimaryDesktop","1.2.840.113556.1.4.2073",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTSPrimaryDesktopBL", new LdapAttributeContext("msTSPrimaryDesktopBL","1.2.840.113556.1.4.2074",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTSProfilePath", new LdapAttributeContext("msTSProfilePath","1.2.840.113556.1.4.1976",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSProperty01", new LdapAttributeContext("msTSProperty01","1.2.840.113556.1.4.1991",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSProperty02", new LdapAttributeContext("msTSProperty02","1.2.840.113556.1.4.1992",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msTSReconnectionAction", new LdapAttributeContext("msTSReconnectionAction","1.2.840.113556.1.4.1984",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "msTSRemoteControl", new LdapAttributeContext("msTSRemoteControl","1.2.840.113556.1.4.1980",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msTSSecondaryDesktopBL", new LdapAttributeContext("msTSSecondaryDesktopBL","1.2.840.113556.1.4.2078",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTSSecondaryDesktops", new LdapAttributeContext("msTSSecondaryDesktops","1.2.840.113556.1.4.2075",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "msTSWorkDirectory", new LdapAttributeContext("msTSWorkDirectory","1.2.840.113556.1.4.1989",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Author", new LdapAttributeContext("msWMI-Author","1.2.840.113556.1.4.1623",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-ChangeDate", new LdapAttributeContext("msWMI-ChangeDate","1.2.840.113556.1.4.1624",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Class", new LdapAttributeContext("msWMI-Class","1.2.840.113556.1.4.1676",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-ClassDefinition", new LdapAttributeContext("msWMI-ClassDefinition","1.2.840.113556.1.4.1625",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-CreationDate", new LdapAttributeContext("msWMI-CreationDate","1.2.840.113556.1.4.1626",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Genus", new LdapAttributeContext("msWMI-Genus","1.2.840.113556.1.4.1677",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-ID", new LdapAttributeContext("msWMI-ID","1.2.840.113556.1.4.1627",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Int8Default", new LdapAttributeContext("msWMI-Int8Default","1.2.840.113556.1.4.1632",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msWMI-Int8Max", new LdapAttributeContext("msWMI-Int8Max","1.2.840.113556.1.4.1633",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msWMI-Int8Min", new LdapAttributeContext("msWMI-Int8Min","1.2.840.113556.1.4.1634",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msWMI-Int8ValidValues", new LdapAttributeContext("msWMI-Int8ValidValues","1.2.840.113556.1.4.1635",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "msWMI-IntDefault", new LdapAttributeContext("msWMI-IntDefault","1.2.840.113556.1.4.1628",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-intFlags1", new LdapAttributeContext("msWMI-intFlags1","1.2.840.113556.1.4.1678",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-intFlags2", new LdapAttributeContext("msWMI-intFlags2","1.2.840.113556.1.4.1679",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-intFlags3", new LdapAttributeContext("msWMI-intFlags3","1.2.840.113556.1.4.1680",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-intFlags4", new LdapAttributeContext("msWMI-intFlags4","1.2.840.113556.1.4.1681",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-IntMax", new LdapAttributeContext("msWMI-IntMax","1.2.840.113556.1.4.1629",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-IntMin", new LdapAttributeContext("msWMI-IntMin","1.2.840.113556.1.4.1630",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-IntValidValues", new LdapAttributeContext("msWMI-IntValidValues","1.2.840.113556.1.4.1631",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "msWMI-Mof", new LdapAttributeContext("msWMI-Mof","1.2.840.113556.1.4.1638",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Name", new LdapAttributeContext("msWMI-Name","1.2.840.113556.1.4.1639",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-NormalizedClass", new LdapAttributeContext("msWMI-NormalizedClass","1.2.840.113556.1.4.1640",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Parm1", new LdapAttributeContext("msWMI-Parm1","1.2.840.113556.1.4.1682",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Parm2", new LdapAttributeContext("msWMI-Parm2","1.2.840.113556.1.4.1683",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Parm3", new LdapAttributeContext("msWMI-Parm3","1.2.840.113556.1.4.1684",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Parm4", new LdapAttributeContext("msWMI-Parm4","1.2.840.113556.1.4.1685",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-PropertyName", new LdapAttributeContext("msWMI-PropertyName","1.2.840.113556.1.4.1641",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-Query", new LdapAttributeContext("msWMI-Query","1.2.840.113556.1.4.1642",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-QueryLanguage", new LdapAttributeContext("msWMI-QueryLanguage","1.2.840.113556.1.4.1643",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-ScopeGuid", new LdapAttributeContext("msWMI-ScopeGuid","1.2.840.113556.1.4.1686",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-SourceOrganization", new LdapAttributeContext("msWMI-SourceOrganization","1.2.840.113556.1.4.1644",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-StringDefault", new LdapAttributeContext("msWMI-StringDefault","1.2.840.113556.1.4.1636",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-StringValidValues", new LdapAttributeContext("msWMI-StringValidValues","1.2.840.113556.1.4.1637",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-TargetClass", new LdapAttributeContext("msWMI-TargetClass","1.2.840.113556.1.4.1645",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-TargetNameSpace", new LdapAttributeContext("msWMI-TargetNameSpace","1.2.840.113556.1.4.1646",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-TargetObject", new LdapAttributeContext("msWMI-TargetObject","1.2.840.113556.1.4.1647",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "msWMI-TargetPath", new LdapAttributeContext("msWMI-TargetPath","1.2.840.113556.1.4.1648",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "msWMI-TargetType", new LdapAttributeContext("msWMI-TargetType","1.2.840.113556.1.4.1649",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "mustContain", new LdapAttributeContext("mustContain","1.2.840.113556.1.2.24",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "name", new LdapAttributeContext("name","1.2.840.113556.1.4.1",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "nameServiceFlags", new LdapAttributeContext("nameServiceFlags","1.2.840.113556.1.4.753",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "nCName", new LdapAttributeContext("nCName","1.2.840.113556.1.2.16",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "nETBIOSName", new LdapAttributeContext("nETBIOSName","1.2.840.113556.1.4.87",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootAllowNewClients", new LdapAttributeContext("netbootAllowNewClients","1.2.840.113556.1.4.849",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "netbootAnswerOnlyValidClients", new LdapAttributeContext("netbootAnswerOnlyValidClients","1.2.840.113556.1.4.854",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "netbootAnswerRequests", new LdapAttributeContext("netbootAnswerRequests","1.2.840.113556.1.4.853",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "netbootCurrentClientCount", new LdapAttributeContext("netbootCurrentClientCount","1.2.840.113556.1.4.852",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "netbootGUID", new LdapAttributeContext("netbootGUID","1.2.840.113556.1.4.359",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "netbootInitialization", new LdapAttributeContext("netbootInitialization","1.2.840.113556.1.4.358",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootIntelliMirrorOSes", new LdapAttributeContext("netbootIntelliMirrorOSes","1.2.840.113556.1.4.857",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootLimitClients", new LdapAttributeContext("netbootLimitClients","1.2.840.113556.1.4.850",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "netbootLocallyInstalledOSes", new LdapAttributeContext("netbootLocallyInstalledOSes","1.2.840.113556.1.4.859",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootMachineFilePath", new LdapAttributeContext("netbootMachineFilePath","1.2.840.113556.1.4.361",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootMaxClients", new LdapAttributeContext("netbootMaxClients","1.2.840.113556.1.4.851",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "netbootMirrorDataFile", new LdapAttributeContext("netbootMirrorDataFile","1.2.840.113556.1.4.1241",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootNewMachineNamingPolicy", new LdapAttributeContext("netbootNewMachineNamingPolicy","1.2.840.113556.1.4.855",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootNewMachineOU", new LdapAttributeContext("netbootNewMachineOU","1.2.840.113556.1.4.856",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "netbootSCPBL", new LdapAttributeContext("netbootSCPBL","1.2.840.113556.1.4.864",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "netbootServer", new LdapAttributeContext("netbootServer","1.2.840.113556.1.4.860",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "netbootSIFFile", new LdapAttributeContext("netbootSIFFile","1.2.840.113556.1.4.1240",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "netbootTools", new LdapAttributeContext("netbootTools","1.2.840.113556.1.4.858",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "networkAddress", new LdapAttributeContext("networkAddress","1.2.840.113556.1.2.459",LdapTokenFormat.StringTeletex,"2.5.5.4",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Teletex,"A case insensitive string that contains characters from the teletex character set.") },
			{ "nextLevelStore", new LdapAttributeContext("nextLevelStore","1.2.840.113556.1.4.214",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "nextRid", new LdapAttributeContext("nextRid","1.2.840.113556.1.4.88",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "nisMapEntry", new LdapAttributeContext("nisMapEntry","1.3.6.1.1.1.1.27",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "nisMapName", new LdapAttributeContext("nisMapName","1.3.6.1.1.1.1.26",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "nisNetgroupTriple", new LdapAttributeContext("nisNetgroupTriple","1.3.6.1.1.1.1.14",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "nonSecurityMember", new LdapAttributeContext("nonSecurityMember","1.2.840.113556.1.4.530",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "nonSecurityMemberBL", new LdapAttributeContext("nonSecurityMemberBL","1.2.840.113556.1.4.531",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "notes", new LdapAttributeContext("notes","1.2.840.113556.1.4.265",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "notificationList", new LdapAttributeContext("notificationList","1.2.840.113556.1.4.303",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "nTGroupMembers", new LdapAttributeContext("nTGroupMembers","1.2.840.113556.1.4.89",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "nTMixedDomain", new LdapAttributeContext("nTMixedDomain","1.2.840.113556.1.4.357",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "ntPwdHistory", new LdapAttributeContext("ntPwdHistory","1.2.840.113556.1.4.94",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "nTSecurityDescriptor", new LdapAttributeContext("nTSecurityDescriptor","1.2.840.113556.1.2.281",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "o", new LdapAttributeContext("o","2.5.4.10",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "objectCategory", new LdapAttributeContext("objectCategory","1.2.840.113556.1.4.782",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "objectClass", new LdapAttributeContext("objectClass","2.5.4.0",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "objectClassCategory", new LdapAttributeContext("objectClassCategory","1.2.840.113556.1.2.370",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "objectClasses", new LdapAttributeContext("objectClasses","2.5.21.6",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "objectCount", new LdapAttributeContext("objectCount","1.2.840.113556.1.4.506",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "objectGUID", new LdapAttributeContext("objectGUID","1.2.840.113556.1.4.2",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "objectSid", new LdapAttributeContext("objectSid","1.2.840.113556.1.4.146",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "objectVersion", new LdapAttributeContext("objectVersion","1.2.840.113556.1.2.76",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "oEMInformation", new LdapAttributeContext("oEMInformation","1.2.840.113556.1.4.151",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "oMObjectClass", new LdapAttributeContext("oMObjectClass","1.2.840.113556.1.2.218",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "oMSyntax", new LdapAttributeContext("oMSyntax","1.2.840.113556.1.2.231",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "oMTGuid", new LdapAttributeContext("oMTGuid","1.2.840.113556.1.4.505",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "oMTIndxGuid", new LdapAttributeContext("oMTIndxGuid","1.2.840.113556.1.4.333",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "oncRpcNumber", new LdapAttributeContext("oncRpcNumber","1.3.6.1.1.1.1.18",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "operatingSystem", new LdapAttributeContext("operatingSystem","1.2.840.113556.1.4.363",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "operatingSystemHotfix", new LdapAttributeContext("operatingSystemHotfix","1.2.840.113556.1.4.415",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "operatingSystemServicePack", new LdapAttributeContext("operatingSystemServicePack","1.2.840.113556.1.4.365",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "operatingSystemVersion", new LdapAttributeContext("operatingSystemVersion","1.2.840.113556.1.4.364",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "operatorCount", new LdapAttributeContext("operatorCount","1.2.840.113556.1.4.144",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "optionDescription", new LdapAttributeContext("optionDescription","1.2.840.113556.1.4.712",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "options", new LdapAttributeContext("options","1.2.840.113556.1.4.307",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "optionsLocation", new LdapAttributeContext("optionsLocation","1.2.840.113556.1.4.713",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "organizationalStatus", new LdapAttributeContext("organizationalStatus","0.9.2342.19200300.100.1.45",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "originalDisplayTable", new LdapAttributeContext("originalDisplayTable","1.2.840.113556.1.2.445",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "originalDisplayTableMSDOS", new LdapAttributeContext("originalDisplayTableMSDOS","1.2.840.113556.1.2.214",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "otherFacsimileTelephoneNumber", new LdapAttributeContext("otherFacsimileTelephoneNumber","1.2.840.113556.1.4.646",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherHomePhone", new LdapAttributeContext("otherHomePhone","1.2.840.113556.1.2.277",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherIpPhone", new LdapAttributeContext("otherIpPhone","1.2.840.113556.1.4.722",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherLoginWorkstations", new LdapAttributeContext("otherLoginWorkstations","1.2.840.113556.1.4.91",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherMailbox", new LdapAttributeContext("otherMailbox","1.2.840.113556.1.4.651",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherMobile", new LdapAttributeContext("otherMobile","1.2.840.113556.1.4.647",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherPager", new LdapAttributeContext("otherPager","1.2.840.113556.1.2.118",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherTelephone", new LdapAttributeContext("otherTelephone","1.2.840.113556.1.2.18",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "otherWellKnownObjects", new LdapAttributeContext("otherWellKnownObjects","1.2.840.113556.1.4.1359",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "ou", new LdapAttributeContext("ou","2.5.4.11",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "owner", new LdapAttributeContext("owner","2.5.4.32",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "ownerBL", new LdapAttributeContext("ownerBL","1.2.840.113556.1.2.104",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "packageFlags", new LdapAttributeContext("packageFlags","1.2.840.113556.1.4.327",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "packageName", new LdapAttributeContext("packageName","1.2.840.113556.1.4.326",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "packageType", new LdapAttributeContext("packageType","1.2.840.113556.1.4.324",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "pager", new LdapAttributeContext("pager","0.9.2342.19200300.100.1.42",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "parentCA", new LdapAttributeContext("parentCA","1.2.840.113556.1.4.557",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "parentCACertificateChain", new LdapAttributeContext("parentCACertificateChain","1.2.840.113556.1.4.685",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "parentGUID", new LdapAttributeContext("parentGUID","1.2.840.113556.1.4.1224",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "partialAttributeDeletionList", new LdapAttributeContext("partialAttributeDeletionList","1.2.840.113556.1.4.663",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "partialAttributeSet", new LdapAttributeContext("partialAttributeSet","1.2.840.113556.1.4.640",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pekKeyChangeInterval", new LdapAttributeContext("pekKeyChangeInterval","1.2.840.113556.1.4.866",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "pekList", new LdapAttributeContext("pekList","1.2.840.113556.1.4.865",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pendingCACertificates", new LdapAttributeContext("pendingCACertificates","1.2.840.113556.1.4.693",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pendingParentCA", new LdapAttributeContext("pendingParentCA","1.2.840.113556.1.4.695",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "perMsgDialogDisplayTable", new LdapAttributeContext("perMsgDialogDisplayTable","1.2.840.113556.1.2.325",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "perRecipDialogDisplayTable", new LdapAttributeContext("perRecipDialogDisplayTable","1.2.840.113556.1.2.326",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "personalTitle", new LdapAttributeContext("personalTitle","1.2.840.113556.1.2.615",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "photo", new LdapAttributeContext("photo","0.9.2342.19200300.100.1.7",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "physicalDeliveryOfficeName", new LdapAttributeContext("physicalDeliveryOfficeName","2.5.4.19",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "physicalLocationObject", new LdapAttributeContext("physicalLocationObject","1.2.840.113556.1.4.514",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "pKICriticalExtensions", new LdapAttributeContext("pKICriticalExtensions","1.2.840.113556.1.4.1330",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "pKIDefaultCSPs", new LdapAttributeContext("pKIDefaultCSPs","1.2.840.113556.1.4.1334",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "pKIDefaultKeySpec", new LdapAttributeContext("pKIDefaultKeySpec","1.2.840.113556.1.4.1327",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "pKIEnrollmentAccess", new LdapAttributeContext("pKIEnrollmentAccess","1.2.840.113556.1.4.1335",LdapTokenFormat.StringNTSecurityDescriptor,"2.5.5.15",LdapAttributeSyntaxADSType.NTSecurityDescriptor,LdapAttributeSyntaxSDSType.IADsSecurityDescriptor,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_NT_Sec_Desc,"An octet string that contains a Windows NT or Windows 2000 security descriptor.") },
			{ "pKIExpirationPeriod", new LdapAttributeContext("pKIExpirationPeriod","1.2.840.113556.1.4.1331",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pKIExtendedKeyUsage", new LdapAttributeContext("pKIExtendedKeyUsage","1.2.840.113556.1.4.1333",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "pKIKeyUsage", new LdapAttributeContext("pKIKeyUsage","1.2.840.113556.1.4.1328",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pKIMaxIssuingDepth", new LdapAttributeContext("pKIMaxIssuingDepth","1.2.840.113556.1.4.1329",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "pKIOverlapPeriod", new LdapAttributeContext("pKIOverlapPeriod","1.2.840.113556.1.4.1332",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pKT", new LdapAttributeContext("pKT","1.2.840.113556.1.4.206",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "pKTGuid", new LdapAttributeContext("pKTGuid","1.2.840.113556.1.4.205",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "policyReplicationFlags", new LdapAttributeContext("policyReplicationFlags","1.2.840.113556.1.4.633",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "portName", new LdapAttributeContext("portName","1.2.840.113556.1.4.228",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "possibleInferiors", new LdapAttributeContext("possibleInferiors","1.2.840.113556.1.4.915",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "possSuperiors", new LdapAttributeContext("possSuperiors","1.2.840.113556.1.2.8",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "postalAddress", new LdapAttributeContext("postalAddress","2.5.4.16",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "postalCode", new LdapAttributeContext("postalCode","2.5.4.17",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "postOfficeBox", new LdapAttributeContext("postOfficeBox","2.5.4.18",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "preferredDeliveryMethod", new LdapAttributeContext("preferredDeliveryMethod","2.5.4.28",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "preferredLanguage", new LdapAttributeContext("preferredLanguage","2.16.840.1.113730.3.1.39",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "preferredOU", new LdapAttributeContext("preferredOU","1.2.840.113556.1.4.97",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "prefixMap", new LdapAttributeContext("prefixMap","1.2.840.113556.1.4.538",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "presentationAddress", new LdapAttributeContext("presentationAddress","2.5.4.29",LdapTokenFormat.StringObjectPresentationAddress,"2.5.5.13",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Object_Presentation_Address,"A string that contains Open Systems Interconnection (OSI) presentation addresses.") },
			{ "previousCACertificates", new LdapAttributeContext("previousCACertificates","1.2.840.113556.1.4.692",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "previousParentCA", new LdapAttributeContext("previousParentCA","1.2.840.113556.1.4.694",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "primaryGroupID", new LdapAttributeContext("primaryGroupID","1.2.840.113556.1.4.98",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "primaryGroupToken", new LdapAttributeContext("primaryGroupToken","1.2.840.113556.1.4.1412",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "primaryInternationalISDNNumber", new LdapAttributeContext("primaryInternationalISDNNumber","1.2.840.113556.1.4.649",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "primaryTelexNumber", new LdapAttributeContext("primaryTelexNumber","1.2.840.113556.1.4.648",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printAttributes", new LdapAttributeContext("printAttributes","1.2.840.113556.1.4.247",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printBinNames", new LdapAttributeContext("printBinNames","1.2.840.113556.1.4.237",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printCollate", new LdapAttributeContext("printCollate","1.2.840.113556.1.4.242",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "printColor", new LdapAttributeContext("printColor","1.2.840.113556.1.4.243",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "printDuplexSupported", new LdapAttributeContext("printDuplexSupported","1.2.840.113556.1.4.1311",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "printEndTime", new LdapAttributeContext("printEndTime","1.2.840.113556.1.4.234",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printerName", new LdapAttributeContext("printerName","1.2.840.113556.1.4.300",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printFormName", new LdapAttributeContext("printFormName","1.2.840.113556.1.4.235",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printKeepPrintedJobs", new LdapAttributeContext("printKeepPrintedJobs","1.2.840.113556.1.4.275",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "printLanguage", new LdapAttributeContext("printLanguage","1.2.840.113556.1.4.246",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printMACAddress", new LdapAttributeContext("printMACAddress","1.2.840.113556.1.4.288",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printMaxCopies", new LdapAttributeContext("printMaxCopies","1.2.840.113556.1.4.241",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMaxResolutionSupported", new LdapAttributeContext("printMaxResolutionSupported","1.2.840.113556.1.4.238",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMaxXExtent", new LdapAttributeContext("printMaxXExtent","1.2.840.113556.1.4.277",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMaxYExtent", new LdapAttributeContext("printMaxYExtent","1.2.840.113556.1.4.278",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMediaReady", new LdapAttributeContext("printMediaReady","1.2.840.113556.1.4.289",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printMediaSupported", new LdapAttributeContext("printMediaSupported","1.2.840.113556.1.4.299",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printMemory", new LdapAttributeContext("printMemory","1.2.840.113556.1.4.282",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMinXExtent", new LdapAttributeContext("printMinXExtent","1.2.840.113556.1.4.279",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printMinYExtent", new LdapAttributeContext("printMinYExtent","1.2.840.113556.1.4.280",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printNetworkAddress", new LdapAttributeContext("printNetworkAddress","1.2.840.113556.1.4.287",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printNotify", new LdapAttributeContext("printNotify","1.2.840.113556.1.4.272",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printNumberUp", new LdapAttributeContext("printNumberUp","1.2.840.113556.1.4.290",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printOrientationsSupported", new LdapAttributeContext("printOrientationsSupported","1.2.840.113556.1.4.240",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printOwner", new LdapAttributeContext("printOwner","1.2.840.113556.1.4.271",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printPagesPerMinute", new LdapAttributeContext("printPagesPerMinute","1.2.840.113556.1.4.631",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printRate", new LdapAttributeContext("printRate","1.2.840.113556.1.4.285",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printRateUnit", new LdapAttributeContext("printRateUnit","1.2.840.113556.1.4.286",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printSeparatorFile", new LdapAttributeContext("printSeparatorFile","1.2.840.113556.1.4.230",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printShareName", new LdapAttributeContext("printShareName","1.2.840.113556.1.4.270",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printSpooling", new LdapAttributeContext("printSpooling","1.2.840.113556.1.4.274",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "printStaplingSupported", new LdapAttributeContext("printStaplingSupported","1.2.840.113556.1.4.281",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "printStartTime", new LdapAttributeContext("printStartTime","1.2.840.113556.1.4.233",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "printStatus", new LdapAttributeContext("printStatus","1.2.840.113556.1.4.273",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "priority", new LdapAttributeContext("priority","1.2.840.113556.1.4.231",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "priorSetTime", new LdapAttributeContext("priorSetTime","1.2.840.113556.1.4.99",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "priorValue", new LdapAttributeContext("priorValue","1.2.840.113556.1.4.100",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "privateKey", new LdapAttributeContext("privateKey","1.2.840.113556.1.4.101",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "privilegeAttributes", new LdapAttributeContext("privilegeAttributes","1.2.840.113556.1.4.636",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "privilegeDisplayName", new LdapAttributeContext("privilegeDisplayName","1.2.840.113556.1.4.634",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "privilegeHolder", new LdapAttributeContext("privilegeHolder","1.2.840.113556.1.4.637",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "privilegeValue", new LdapAttributeContext("privilegeValue","1.2.840.113556.1.4.635",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "productCode", new LdapAttributeContext("productCode","1.2.840.113556.1.4.818",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "profilePath", new LdapAttributeContext("profilePath","1.2.840.113556.1.4.139",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "proxiedObjectName", new LdapAttributeContext("proxiedObjectName","1.2.840.113556.1.4.1249",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "proxyAddresses", new LdapAttributeContext("proxyAddresses","1.2.840.113556.1.2.210",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "proxyGenerationEnabled", new LdapAttributeContext("proxyGenerationEnabled","1.2.840.113556.1.2.523",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "proxyLifetime", new LdapAttributeContext("proxyLifetime","1.2.840.113556.1.4.103",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "publicKeyPolicy", new LdapAttributeContext("publicKeyPolicy","1.2.840.113556.1.4.420",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "purportedSearch", new LdapAttributeContext("purportedSearch","1.2.840.113556.1.4.886",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "pwdHistoryLength", new LdapAttributeContext("pwdHistoryLength","1.2.840.113556.1.4.95",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "pwdLastSet", new LdapAttributeContext("pwdLastSet","1.2.840.113556.1.4.96",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "pwdProperties", new LdapAttributeContext("pwdProperties","1.2.840.113556.1.4.93",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "qualityOfService", new LdapAttributeContext("qualityOfService","1.2.840.113556.1.4.458",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "queryFilter", new LdapAttributeContext("queryFilter","1.2.840.113556.1.4.1355",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "queryPoint", new LdapAttributeContext("queryPoint","1.2.840.113556.1.4.680",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "queryPolicyBL", new LdapAttributeContext("queryPolicyBL","1.2.840.113556.1.4.608",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "queryPolicyObject", new LdapAttributeContext("queryPolicyObject","1.2.840.113556.1.4.607",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "rangeLower", new LdapAttributeContext("rangeLower","1.2.840.113556.1.2.34",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rangeUpper", new LdapAttributeContext("rangeUpper","1.2.840.113556.1.2.35",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rDNAttID", new LdapAttributeContext("rDNAttID","1.2.840.113556.1.2.26",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "registeredAddress", new LdapAttributeContext("registeredAddress","2.5.4.26",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "remoteServerName", new LdapAttributeContext("remoteServerName","1.2.840.113556.1.4.105",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "remoteSource", new LdapAttributeContext("remoteSource","1.2.840.113556.1.4.107",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "remoteSourceType", new LdapAttributeContext("remoteSourceType","1.2.840.113556.1.4.108",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "remoteStorageGUID", new LdapAttributeContext("remoteStorageGUID","1.2.840.113556.1.4.809",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "replicaSource", new LdapAttributeContext("replicaSource","1.2.840.113556.1.4.109",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "replInterval", new LdapAttributeContext("replInterval","1.2.840.113556.1.4.1336",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "replPropertyMetaData", new LdapAttributeContext("replPropertyMetaData","1.2.840.113556.1.4.3",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "replTopologyStayOfExecution", new LdapAttributeContext("replTopologyStayOfExecution","1.2.840.113556.1.4.677",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "replUpToDateVector", new LdapAttributeContext("replUpToDateVector","1.2.840.113556.1.4.4",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "repsFrom", new LdapAttributeContext("repsFrom","1.2.840.113556.1.2.91",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "repsTo", new LdapAttributeContext("repsTo","1.2.840.113556.1.2.83",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "requiredCategories", new LdapAttributeContext("requiredCategories","1.2.840.113556.1.4.321",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "retiredReplDSASignatures", new LdapAttributeContext("retiredReplDSASignatures","1.2.840.113556.1.4.673",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "revision", new LdapAttributeContext("revision","1.2.840.113556.1.4.145",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rid", new LdapAttributeContext("rid","1.2.840.113556.1.4.153",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rIDAllocationPool", new LdapAttributeContext("rIDAllocationPool","1.2.840.113556.1.4.371",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "rIDAvailablePool", new LdapAttributeContext("rIDAvailablePool","1.2.840.113556.1.4.370",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "rIDManagerReference", new LdapAttributeContext("rIDManagerReference","1.2.840.113556.1.4.368",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "rIDNextRID", new LdapAttributeContext("rIDNextRID","1.2.840.113556.1.4.374",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rIDPreviousAllocationPool", new LdapAttributeContext("rIDPreviousAllocationPool","1.2.840.113556.1.4.372",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "rIDSetReferences", new LdapAttributeContext("rIDSetReferences","1.2.840.113556.1.4.669",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "rIDUsedPool", new LdapAttributeContext("rIDUsedPool","1.2.840.113556.1.4.373",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "rightsGuid", new LdapAttributeContext("rightsGuid","1.2.840.113556.1.4.340",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "roleOccupant", new LdapAttributeContext("roleOccupant","2.5.4.33",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "roomNumber", new LdapAttributeContext("roomNumber","0.9.2342.19200300.100.1.6",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rootTrust", new LdapAttributeContext("rootTrust","1.2.840.113556.1.4.674",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "rpcNsAnnotation", new LdapAttributeContext("rpcNsAnnotation","1.2.840.113556.1.4.366",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsBindings", new LdapAttributeContext("rpcNsBindings","1.2.840.113556.1.4.113",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsCodeset", new LdapAttributeContext("rpcNsCodeset","1.2.840.113556.1.4.367",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsEntryFlags", new LdapAttributeContext("rpcNsEntryFlags","1.2.840.113556.1.4.754",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rpcNsGroup", new LdapAttributeContext("rpcNsGroup","1.2.840.113556.1.4.114",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsInterfaceID", new LdapAttributeContext("rpcNsInterfaceID","1.2.840.113556.1.4.115",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsObjectID", new LdapAttributeContext("rpcNsObjectID","1.2.840.113556.1.4.312",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsPriority", new LdapAttributeContext("rpcNsPriority","1.2.840.113556.1.4.117",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "rpcNsProfileEntry", new LdapAttributeContext("rpcNsProfileEntry","1.2.840.113556.1.4.118",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "rpcNsTransferSyntax", new LdapAttributeContext("rpcNsTransferSyntax","1.2.840.113556.1.4.314",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "sAMAccountName", new LdapAttributeContext("sAMAccountName","1.2.840.113556.1.4.221",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "sAMAccountType", new LdapAttributeContext("sAMAccountType","1.2.840.113556.1.4.302",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "samDomainUpdates", new LdapAttributeContext("samDomainUpdates","1.2.840.113556.1.4.1969",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "schedule", new LdapAttributeContext("schedule","1.2.840.113556.1.4.211",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "schemaFlagsEx", new LdapAttributeContext("schemaFlagsEx","1.2.840.113556.1.4.120",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "schemaIDGUID", new LdapAttributeContext("schemaIDGUID","1.2.840.113556.1.4.148",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "schemaInfo", new LdapAttributeContext("schemaInfo","1.2.840.113556.1.4.1358",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "schemaUpdate", new LdapAttributeContext("schemaUpdate","1.2.840.113556.1.4.481",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "schemaVersion", new LdapAttributeContext("schemaVersion","1.2.840.113556.1.2.471",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "scopeFlags", new LdapAttributeContext("scopeFlags","1.2.840.113556.1.4.1354",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "scriptPath", new LdapAttributeContext("scriptPath","1.2.840.113556.1.4.62",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "sDRightsEffective", new LdapAttributeContext("sDRightsEffective","1.2.840.113556.1.4.1304",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "searchFlags", new LdapAttributeContext("searchFlags","1.2.840.113556.1.2.334",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "searchGuide", new LdapAttributeContext("searchGuide","2.5.4.14",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "secretary", new LdapAttributeContext("secretary","0.9.2342.19200300.100.1.21",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "securityIdentifier", new LdapAttributeContext("securityIdentifier","1.2.840.113556.1.4.121",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "seeAlso", new LdapAttributeContext("seeAlso","2.5.4.34",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "seqNotification", new LdapAttributeContext("seqNotification","1.2.840.113556.1.4.504",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "serialNumber", new LdapAttributeContext("serialNumber","2.5.4.5",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "serverName", new LdapAttributeContext("serverName","1.2.840.113556.1.4.223",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "serverReference", new LdapAttributeContext("serverReference","1.2.840.113556.1.4.515",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "serverReferenceBL", new LdapAttributeContext("serverReferenceBL","1.2.840.113556.1.4.516",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "serverRole", new LdapAttributeContext("serverRole","1.2.840.113556.1.4.157",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "serverState", new LdapAttributeContext("serverState","1.2.840.113556.1.4.154",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "serviceBindingInformation", new LdapAttributeContext("serviceBindingInformation","1.2.840.113556.1.4.510",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "serviceClassID", new LdapAttributeContext("serviceClassID","1.2.840.113556.1.4.122",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "serviceClassInfo", new LdapAttributeContext("serviceClassInfo","1.2.840.113556.1.4.123",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "serviceClassName", new LdapAttributeContext("serviceClassName","1.2.840.113556.1.4.509",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "serviceDNSName", new LdapAttributeContext("serviceDNSName","1.2.840.113556.1.4.657",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "serviceDNSNameType", new LdapAttributeContext("serviceDNSNameType","1.2.840.113556.1.4.659",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "serviceInstanceVersion", new LdapAttributeContext("serviceInstanceVersion","1.2.840.113556.1.4.199",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "servicePrincipalName", new LdapAttributeContext("servicePrincipalName","1.2.840.113556.1.4.771",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "setupCommand", new LdapAttributeContext("setupCommand","1.2.840.113556.1.4.325",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "shadowExpire", new LdapAttributeContext("shadowExpire","1.3.6.1.1.1.1.10",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowFlag", new LdapAttributeContext("shadowFlag","1.3.6.1.1.1.1.11",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowInactive", new LdapAttributeContext("shadowInactive","1.3.6.1.1.1.1.9",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowLastChange", new LdapAttributeContext("shadowLastChange","1.3.6.1.1.1.1.5",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowMax", new LdapAttributeContext("shadowMax","1.3.6.1.1.1.1.7",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowMin", new LdapAttributeContext("shadowMin","1.3.6.1.1.1.1.6",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shadowWarning", new LdapAttributeContext("shadowWarning","1.3.6.1.1.1.1.8",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "shellContextMenu", new LdapAttributeContext("shellContextMenu","1.2.840.113556.1.4.615",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "shellPropertyPages", new LdapAttributeContext("shellPropertyPages","1.2.840.113556.1.4.563",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "shortServerName", new LdapAttributeContext("shortServerName","1.2.840.113556.1.4.1209",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "showInAddressBook", new LdapAttributeContext("showInAddressBook","1.2.840.113556.1.4.644",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "showInAdvancedViewOnly", new LdapAttributeContext("showInAdvancedViewOnly","1.2.840.113556.1.2.169",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "sIDHistory", new LdapAttributeContext("sIDHistory","1.2.840.113556.1.4.609",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "signatureAlgorithms", new LdapAttributeContext("signatureAlgorithms","1.2.840.113556.1.4.824",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "siteGUID", new LdapAttributeContext("siteGUID","1.2.840.113556.1.4.362",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "siteLinkList", new LdapAttributeContext("siteLinkList","1.2.840.113556.1.4.822",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "siteList", new LdapAttributeContext("siteList","1.2.840.113556.1.4.821",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "siteObject", new LdapAttributeContext("siteObject","1.2.840.113556.1.4.512",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "siteObjectBL", new LdapAttributeContext("siteObjectBL","1.2.840.113556.1.4.513",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "siteServer", new LdapAttributeContext("siteServer","1.2.840.113556.1.4.494",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "sn", new LdapAttributeContext("sn","2.5.4.4",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "sPNMappings", new LdapAttributeContext("sPNMappings","1.2.840.113556.1.4.1347",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "st", new LdapAttributeContext("st","2.5.4.8",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "street", new LdapAttributeContext("street","2.5.4.9",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "streetAddress", new LdapAttributeContext("streetAddress","1.2.840.113556.1.2.256",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "structuralObjectClass", new LdapAttributeContext("structuralObjectClass","2.5.21.9",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "subClassOf", new LdapAttributeContext("subClassOf","1.2.840.113556.1.2.21",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "subRefs", new LdapAttributeContext("subRefs","1.2.840.113556.1.2.7",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "subSchemaSubEntry", new LdapAttributeContext("subSchemaSubEntry","2.5.18.10",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "superiorDNSRoot", new LdapAttributeContext("superiorDNSRoot","1.2.840.113556.1.4.532",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "superScopeDescription", new LdapAttributeContext("superScopeDescription","1.2.840.113556.1.4.711",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "superScopes", new LdapAttributeContext("superScopes","1.2.840.113556.1.4.710",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "supplementalCredentials", new LdapAttributeContext("supplementalCredentials","1.2.840.113556.1.4.125",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "supportedApplicationContext", new LdapAttributeContext("supportedApplicationContext","2.5.4.30",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "syncAttributes", new LdapAttributeContext("syncAttributes","1.2.840.113556.1.4.666",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "syncMembership", new LdapAttributeContext("syncMembership","1.2.840.113556.1.4.665",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "syncWithObject", new LdapAttributeContext("syncWithObject","1.2.840.113556.1.4.664",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "syncWithSID", new LdapAttributeContext("syncWithSID","1.2.840.113556.1.4.667",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "systemAuxiliaryClass", new LdapAttributeContext("systemAuxiliaryClass","1.2.840.113556.1.4.198",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "systemFlags", new LdapAttributeContext("systemFlags","1.2.840.113556.1.4.375",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "systemMayContain", new LdapAttributeContext("systemMayContain","1.2.840.113556.1.4.196",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "systemMustContain", new LdapAttributeContext("systemMustContain","1.2.840.113556.1.4.197",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "systemOnly", new LdapAttributeContext("systemOnly","1.2.840.113556.1.4.170",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "systemPossSuperiors", new LdapAttributeContext("systemPossSuperiors","1.2.840.113556.1.4.195",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "telephoneNumber", new LdapAttributeContext("telephoneNumber","2.5.4.20",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "teletexTerminalIdentifier", new LdapAttributeContext("teletexTerminalIdentifier","2.5.4.22",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "telexNumber", new LdapAttributeContext("telexNumber","2.5.4.21",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "templateRoots", new LdapAttributeContext("templateRoots","1.2.840.113556.1.4.1346",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "templateRoots2", new LdapAttributeContext("templateRoots2","1.2.840.113556.1.4.2048",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "terminalServer", new LdapAttributeContext("terminalServer","1.2.840.113556.1.4.885",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "textEncodedORAddress", new LdapAttributeContext("textEncodedORAddress","0.9.2342.19200300.100.1.2",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "thumbnailLogo", new LdapAttributeContext("thumbnailLogo","2.16.840.1.113730.3.1.36",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "thumbnailPhoto", new LdapAttributeContext("thumbnailPhoto","2.16.840.1.113730.3.1.35",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "timeRefresh", new LdapAttributeContext("timeRefresh","1.2.840.113556.1.4.503",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "timeVolChange", new LdapAttributeContext("timeVolChange","1.2.840.113556.1.4.502",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "title", new LdapAttributeContext("title","2.5.4.12",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "tokenGroups", new LdapAttributeContext("tokenGroups","1.2.840.113556.1.4.1301",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "tokenGroupsGlobalAndUniversal", new LdapAttributeContext("tokenGroupsGlobalAndUniversal","1.2.840.113556.1.4.1418",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "tokenGroupsNoGCAcceptable", new LdapAttributeContext("tokenGroupsNoGCAcceptable","1.2.840.113556.1.4.1303",LdapTokenFormat.SID,"2.5.5.17",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.String_Sid,"An octet string that contains a security identifier (SID).") },
			{ "tombstoneLifetime", new LdapAttributeContext("tombstoneLifetime","1.2.840.113556.1.2.54",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "transportAddressAttribute", new LdapAttributeContext("transportAddressAttribute","1.2.840.113556.1.4.895",LdapTokenFormat.StringObjectIdentifier,"2.5.5.2",LdapAttributeSyntaxADSType.CaseIgnoreString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.String_Object_Identifier,"An OID string which is a string that contains digits (0-9) and decimal points (.).") },
			{ "transportDLLName", new LdapAttributeContext("transportDLLName","1.2.840.113556.1.4.789",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "transportType", new LdapAttributeContext("transportType","1.2.840.113556.1.4.791",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "treatAsLeaf", new LdapAttributeContext("treatAsLeaf","1.2.840.113556.1.4.806",LdapTokenFormat.Boolean,"2.5.5.8",LdapAttributeSyntaxADSType.Boolean,LdapAttributeSyntaxSDSType.Boolean,LdapAttributeSyntaxMAPIType.Boolean,LdapAttributeSyntaxTitle.Boolean,"Represents a Boolean value.") },
			{ "treeName", new LdapAttributeContext("treeName","1.2.840.113556.1.4.660",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "trustAttributes", new LdapAttributeContext("trustAttributes","1.2.840.113556.1.4.470",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "trustAuthIncoming", new LdapAttributeContext("trustAuthIncoming","1.2.840.113556.1.4.129",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "trustAuthOutgoing", new LdapAttributeContext("trustAuthOutgoing","1.2.840.113556.1.4.135",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "trustDirection", new LdapAttributeContext("trustDirection","1.2.840.113556.1.4.132",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "trustParent", new LdapAttributeContext("trustParent","1.2.840.113556.1.4.471",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "trustPartner", new LdapAttributeContext("trustPartner","1.2.840.113556.1.4.133",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "trustPosixOffset", new LdapAttributeContext("trustPosixOffset","1.2.840.113556.1.4.134",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "trustType", new LdapAttributeContext("trustType","1.2.840.113556.1.4.136",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "uASCompat", new LdapAttributeContext("uASCompat","1.2.840.113556.1.4.155",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "uid", new LdapAttributeContext("uid","0.9.2342.19200300.100.1.1",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "uidNumber", new LdapAttributeContext("uidNumber","1.3.6.1.1.1.1.0",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "uNCName", new LdapAttributeContext("uNCName","1.2.840.113556.1.4.137",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "unicodePwd", new LdapAttributeContext("unicodePwd","1.2.840.113556.1.4.90",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "uniqueIdentifier", new LdapAttributeContext("uniqueIdentifier","0.9.2342.19200300.100.1.44",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "uniqueMember", new LdapAttributeContext("uniqueMember","2.5.4.50",LdapTokenFormat.DNString,"2.5.5.1",LdapAttributeSyntaxADSType.DNString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.Object,LdapAttributeSyntaxTitle.Object_DS_DN,"String that contains a distinguished name (DN).") },
			{ "unixHomeDirectory", new LdapAttributeContext("unixHomeDirectory","1.3.6.1.1.1.1.3",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "unixUserPassword", new LdapAttributeContext("unixUserPassword","1.2.840.113556.1.4.1910",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "unstructuredAddress", new LdapAttributeContext("unstructuredAddress","1.2.840.113549.1.9.8",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "unstructuredName", new LdapAttributeContext("unstructuredName","1.2.840.113549.1.9.2",LdapTokenFormat.StringIA5,"2.5.5.5",LdapAttributeSyntaxADSType.PrintableString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_IA5,"A case-sensitive string that contains characters from the IA5 character set.") },
			{ "upgradeProductCode", new LdapAttributeContext("upgradeProductCode","1.2.840.113556.1.4.813",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "uPNSuffixes", new LdapAttributeContext("uPNSuffixes","1.2.840.113556.1.4.890",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "url", new LdapAttributeContext("url","1.2.840.113556.1.4.749",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userAccountControl", new LdapAttributeContext("userAccountControl","1.2.840.113556.1.4.8",LdapTokenFormat.Bitwise,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "userCert", new LdapAttributeContext("userCert","1.2.840.113556.1.4.645",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "userCertificate", new LdapAttributeContext("userCertificate","2.5.4.36",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "userClass", new LdapAttributeContext("userClass","0.9.2342.19200300.100.1.8",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userParameters", new LdapAttributeContext("userParameters","1.2.840.113556.1.4.138",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userPassword", new LdapAttributeContext("userPassword","2.5.4.35",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "userPKCS12", new LdapAttributeContext("userPKCS12","2.16.840.1.113730.3.1.216",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "userPrincipalName", new LdapAttributeContext("userPrincipalName","1.2.840.113556.1.4.656",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userSharedFolder", new LdapAttributeContext("userSharedFolder","1.2.840.113556.1.4.751",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userSharedFolderOther", new LdapAttributeContext("userSharedFolderOther","1.2.840.113556.1.4.752",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "userSMIMECertificate", new LdapAttributeContext("userSMIMECertificate","2.16.840.1.113730.3.140",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "userWorkstations", new LdapAttributeContext("userWorkstations","1.2.840.113556.1.4.86",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "uSNChanged", new LdapAttributeContext("uSNChanged","1.2.840.113556.1.2.120",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "uSNCreated", new LdapAttributeContext("uSNCreated","1.2.840.113556.1.2.19",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "uSNDSALastObjRemoved", new LdapAttributeContext("uSNDSALastObjRemoved","1.2.840.113556.1.2.267",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "USNIntersite", new LdapAttributeContext("USNIntersite","1.2.840.113556.1.2.469",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "uSNLastObjRem", new LdapAttributeContext("uSNLastObjRem","1.2.840.113556.1.2.121",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "uSNSource", new LdapAttributeContext("uSNSource","1.2.840.113556.1.4.896",LdapTokenFormat.IntTimeInterval,"2.5.5.16",LdapAttributeSyntaxADSType.LargeInteger,LdapAttributeSyntaxSDSType.IADsLargeInteger,LdapAttributeSyntaxMAPIType.Undefined,LdapAttributeSyntaxTitle.Interval,"Represents a time interval value.") },
			{ "validAccesses", new LdapAttributeContext("validAccesses","1.2.840.113556.1.4.1356",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "vendor", new LdapAttributeContext("vendor","1.2.840.113556.1.4.255",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "versionNumber", new LdapAttributeContext("versionNumber","1.2.840.113556.1.4.141",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "versionNumberHi", new LdapAttributeContext("versionNumberHi","1.2.840.113556.1.4.328",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "versionNumberLo", new LdapAttributeContext("versionNumberLo","1.2.840.113556.1.4.329",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "volTableGUID", new LdapAttributeContext("volTableGUID","1.2.840.113556.1.4.336",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "volTableIdxGUID", new LdapAttributeContext("volTableIdxGUID","1.2.840.113556.1.4.334",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "volumeCount", new LdapAttributeContext("volumeCount","1.2.840.113556.1.4.507",LdapTokenFormat.IntEnumeration,"2.5.5.9",LdapAttributeSyntaxADSType.Integer,LdapAttributeSyntaxSDSType.Int32,LdapAttributeSyntaxMAPIType.Long,LdapAttributeSyntaxTitle.Enumeration,"Enumeration(delivery-mechanism) syntax.") },
			{ "wbemPath", new LdapAttributeContext("wbemPath","1.2.840.113556.1.4.301",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "wellKnownObjects", new LdapAttributeContext("wellKnownObjects","1.2.840.113556.1.4.618",LdapTokenFormat.DNWithBinary,"2.5.5.7",LdapAttributeSyntaxADSType.DNWithBinary,LdapAttributeSyntaxSDSType.IADsDNWithBinary,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.Object_DN_Binary,"An octet string that contains a binary value and a distinguished name (DN).") },
			{ "whenChanged", new LdapAttributeContext("whenChanged","1.2.840.113556.1.2.3",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "whenCreated", new LdapAttributeContext("whenCreated","1.2.840.113556.1.2.2",LdapTokenFormat.DateTime,"2.5.5.11",LdapAttributeSyntaxADSType.UTCTime,LdapAttributeSyntaxSDSType.DateTime,LdapAttributeSyntaxMAPIType.Systime,LdapAttributeSyntaxTitle.String_Generalized_Time,"A time string format defined by ASN.1 standards.") },
			{ "winsockAddresses", new LdapAttributeContext("winsockAddresses","1.2.840.113556.1.4.142",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
			{ "wWWHomePage", new LdapAttributeContext("wWWHomePage","1.2.840.113556.1.2.464",LdapTokenFormat.StringUnicode,"2.5.5.12",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Unicode,"A case-insensitive Unicode string.") },
			{ "x121Address", new LdapAttributeContext("x121Address","2.5.4.24",LdapTokenFormat.StringNumeric,"2.5.5.6",LdapAttributeSyntaxADSType.NumericString,LdapAttributeSyntaxSDSType.String,LdapAttributeSyntaxMAPIType.TString,LdapAttributeSyntaxTitle.String_Numeric,"A string that contains digits.") },
			{ "x500uniqueIdentifier", new LdapAttributeContext("x500uniqueIdentifier","2.5.4.45",LdapTokenFormat.HexObjectReplicaLink,"2.5.5.10",LdapAttributeSyntaxADSType.OctetString,LdapAttributeSyntaxSDSType.ByteArray,LdapAttributeSyntaxMAPIType.Binary,LdapAttributeSyntaxTitle.Object_Replica_Link,"Object(Replica-Link) syntax.") },
		};

		/// <summary>
		/// This method returns full Context object for input Attribute value (regardless of format or potential obfuscation).
		/// </summary>
		public static LdapAttributeContext GetLdapAttribute(string ldapAttribute)
		{
			// Return empty LdapAttributeContext object if input ldapAttribute string is null or empty.
			if (ldapAttribute.Length == 0)
			{
				return new LdapAttributeContext();
			}

			// If input Attribute is in OID format then normalize OID and return Attribute name if defined in Attribute Dictionary.
			if (LdapParser.IsOid(ldapAttribute))
			{
				// Normalize Attribute in case any OID-specific obfuscation is present.
				string ldapAttributeOidNormalized = LdapParser.NormalizeOid(ldapAttribute);

				// If input Attribute OID is not defined in Attribute OID Dictionary then return empty LdapAttributeContext object.
				if (!ldapAttributeOidDict.ContainsKey(ldapAttributeOidNormalized))
				{
					return new LdapAttributeContext();
				}

				// Update normalized input Attribute with name from OID Dictionary.
				ldapAttribute = ldapAttributeOidDict[ldapAttributeOidNormalized];
			}

			// If input Attribute name is not defined in Attribute context Dictionary then return empty LdapAttributeContext object.
			if (!ldapAttributeContextDict.ContainsKey(ldapAttribute))
			{
				return new LdapAttributeContext();
			}

			// Return Attribute Context object returned from Dictionary.
			return ldapAttributeContextDict[ldapAttribute];
		}

		/// <summary>
		/// This Dictionary defines all ASCII characters and corresponding character metadata used for efficient lookups in LDAP Value parsing and feature extraction purposes.
		/// </summary>
		public static readonly IReadOnlyDictionary<char, CharContext> charContextDict = new Dictionary<char, CharContext>()
		{
			{ '\u0000', new CharContext('\u0000',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0001', new CharContext('\u0001',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0002', new CharContext('\u0002',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0003', new CharContext('\u0003',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0004', new CharContext('\u0004',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0005', new CharContext('\u0005',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0006', new CharContext('\u0006',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0007', new CharContext('\u0007',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0008', new CharContext('\u0008',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0009', new CharContext('\u0009',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000A', new CharContext('\u000A',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000B', new CharContext('\u000B',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000C', new CharContext('\u000C',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000D', new CharContext('\u000D',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000E', new CharContext('\u000E',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u000F', new CharContext('\u000F',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0010', new CharContext('\u0010',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0011', new CharContext('\u0011',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0012', new CharContext('\u0012',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0013', new CharContext('\u0013',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0014', new CharContext('\u0014',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0015', new CharContext('\u0015',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0016', new CharContext('\u0016',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0017', new CharContext('\u0017',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0018', new CharContext('\u0018',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0019', new CharContext('\u0019',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001A', new CharContext('\u001A',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001B', new CharContext('\u001B',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001C', new CharContext('\u001C',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001D', new CharContext('\u001D',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001E', new CharContext('\u001E',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u001F', new CharContext('\u001F',CharClass.ControlC0,CharCase.NA,false,false) },
			{ ' ', new CharContext(' ',CharClass.Special,CharCase.NA,true,false) },
			{ '!', new CharContext('!',CharClass.Special,CharCase.NA,true,false) },
			{ '"', new CharContext('"',CharClass.Special,CharCase.NA,true,false) },
			{ '#', new CharContext('#',CharClass.Special,CharCase.NA,true,false) },
			{ '$', new CharContext('$',CharClass.Special,CharCase.NA,true,false) },
			{ '%', new CharContext('%',CharClass.Special,CharCase.NA,true,false) },
			{ '&', new CharContext('&',CharClass.Special,CharCase.NA,true,false) },
			{ '\'', new CharContext('\'',CharClass.Special,CharCase.NA,true,false) },
			{ '(', new CharContext('(',CharClass.Special,CharCase.NA,true,false) },
			{ ')', new CharContext(')',CharClass.Special,CharCase.NA,true,false) },
			{ '*', new CharContext('*',CharClass.Special,CharCase.NA,true,false) },
			{ '+', new CharContext('+',CharClass.Special,CharCase.NA,true,false) },
			{ ',', new CharContext(',',CharClass.Special,CharCase.NA,true,false) },
			{ '-', new CharContext('-',CharClass.Special,CharCase.NA,true,false) },
			{ '.', new CharContext('.',CharClass.Special,CharCase.NA,true,false) },
			{ '/', new CharContext('/',CharClass.Special,CharCase.NA,true,false) },
			{ '0', new CharContext('0',CharClass.Num,CharCase.NA,true,true) },
			{ '1', new CharContext('1',CharClass.Num,CharCase.NA,true,true) },
			{ '2', new CharContext('2',CharClass.Num,CharCase.NA,true,true) },
			{ '3', new CharContext('3',CharClass.Num,CharCase.NA,true,true) },
			{ '4', new CharContext('4',CharClass.Num,CharCase.NA,true,true) },
			{ '5', new CharContext('5',CharClass.Num,CharCase.NA,true,true) },
			{ '6', new CharContext('6',CharClass.Num,CharCase.NA,true,true) },
			{ '7', new CharContext('7',CharClass.Num,CharCase.NA,true,true) },
			{ '8', new CharContext('8',CharClass.Num,CharCase.NA,true,true) },
			{ '9', new CharContext('9',CharClass.Num,CharCase.NA,true,true) },
			{ ':', new CharContext(':',CharClass.Special,CharCase.NA,true,false) },
			{ ';', new CharContext(';',CharClass.Special,CharCase.NA,true,false) },
			{ '<', new CharContext('<',CharClass.Special,CharCase.NA,true,false) },
			{ '=', new CharContext('=',CharClass.Special,CharCase.NA,true,false) },
			{ '>', new CharContext('>',CharClass.Special,CharCase.NA,true,false) },
			{ '?', new CharContext('?',CharClass.Special,CharCase.NA,true,false) },
			{ '@', new CharContext('@',CharClass.Special,CharCase.NA,true,false) },
			{ 'A', new CharContext('A',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'B', new CharContext('B',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'C', new CharContext('C',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'D', new CharContext('D',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'E', new CharContext('E',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'F', new CharContext('F',CharClass.Alpha,CharCase.Upper,true,true) },
			{ 'G', new CharContext('G',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'H', new CharContext('H',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'I', new CharContext('I',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'J', new CharContext('J',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'K', new CharContext('K',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'L', new CharContext('L',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'M', new CharContext('M',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'N', new CharContext('N',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'O', new CharContext('O',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'P', new CharContext('P',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'Q', new CharContext('Q',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'R', new CharContext('R',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'S', new CharContext('S',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'T', new CharContext('T',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'U', new CharContext('U',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'V', new CharContext('V',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'W', new CharContext('W',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'X', new CharContext('X',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'Y', new CharContext('Y',CharClass.Alpha,CharCase.Upper,true,false) },
			{ 'Z', new CharContext('Z',CharClass.Alpha,CharCase.Upper,true,false) },
			{ '[', new CharContext('[',CharClass.Special,CharCase.NA,true,false) },
			{ '\\', new CharContext('\\',CharClass.Special,CharCase.NA,true,false) },
			{ ']', new CharContext(']',CharClass.Special,CharCase.NA,true,false) },
			{ '^', new CharContext('^',CharClass.Special,CharCase.NA,true,false) },
			{ '_', new CharContext('_',CharClass.Special,CharCase.NA,true,false) },
			{ '`', new CharContext('`',CharClass.Special,CharCase.NA,true,false) },
			{ 'a', new CharContext('a',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'b', new CharContext('b',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'c', new CharContext('c',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'd', new CharContext('d',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'e', new CharContext('e',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'f', new CharContext('f',CharClass.Alpha,CharCase.Lower,true,true) },
			{ 'g', new CharContext('g',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'h', new CharContext('h',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'i', new CharContext('i',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'j', new CharContext('j',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'k', new CharContext('k',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'l', new CharContext('l',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'm', new CharContext('m',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'n', new CharContext('n',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'o', new CharContext('o',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'p', new CharContext('p',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'q', new CharContext('q',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'r', new CharContext('r',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 's', new CharContext('s',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 't', new CharContext('t',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'u', new CharContext('u',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'v', new CharContext('v',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'w', new CharContext('w',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'x', new CharContext('x',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'y', new CharContext('y',CharClass.Alpha,CharCase.Lower,true,false) },
			{ 'z', new CharContext('z',CharClass.Alpha,CharCase.Lower,true,false) },
			{ '{', new CharContext('{',CharClass.Special,CharCase.NA,true,false) },
			{ '|', new CharContext('|',CharClass.Special,CharCase.NA,true,false) },
			{ '}', new CharContext('}',CharClass.Special,CharCase.NA,true,false) },
			{ '~', new CharContext('~',CharClass.Special,CharCase.NA,true,false) },
			{ '\u007F', new CharContext('\u007F',CharClass.ControlC0,CharCase.NA,false,false) },
			{ '\u0080', new CharContext('\u0080',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0081', new CharContext('\u0081',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0082', new CharContext('\u0082',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0083', new CharContext('\u0083',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0084', new CharContext('\u0084',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0085', new CharContext('\u0085',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0086', new CharContext('\u0086',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0087', new CharContext('\u0087',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0088', new CharContext('\u0088',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0089', new CharContext('\u0089',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008A', new CharContext('\u008A',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008B', new CharContext('\u008B',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008C', new CharContext('\u008C',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008D', new CharContext('\u008D',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008E', new CharContext('\u008E',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u008F', new CharContext('\u008F',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0090', new CharContext('\u0090',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0091', new CharContext('\u0091',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0092', new CharContext('\u0092',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0093', new CharContext('\u0093',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0094', new CharContext('\u0094',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0095', new CharContext('\u0095',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0096', new CharContext('\u0096',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0097', new CharContext('\u0097',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0098', new CharContext('\u0098',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u0099', new CharContext('\u0099',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009A', new CharContext('\u009A',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009B', new CharContext('\u009B',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009C', new CharContext('\u009C',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009D', new CharContext('\u009D',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009E', new CharContext('\u009E',CharClass.ControlC1,CharCase.NA,false,false) },
			{ '\u009F', new CharContext('\u009F',CharClass.ControlC1,CharCase.NA,false,false) },
		};

		/// <summary>
		/// This method returns full Context object for input Attribute Value (regardless of format or potential obfuscation).
		/// </summary>
		public static LdapValueContext GetLdapValue(string ldapValue, bool isDn = false)
		{
			// Return empty LdapValueContext object if input ldapValue string is null or empty.
			if (ldapValue.Length == 0)
			{
				return new LdapValueContext();
			}

			// Fully parse input ldapValue string (including escaped and hex encoded characters).
			List<LdapValueParsed> contentParsedList = ParseLdapValue(ldapValue, isDn);

			// Create Attribute Value Context object based on above parsed list of ldapValue characters.
			LdapValueContext ldapValueContext = new LdapValueContext(contentParsedList);

			// Return Attribute Value Context object.
			return ldapValueContext;
		}

		/// <summary>
		/// This method returns fully parsed input Attribute Value (including escaped and hex encoded characters).
		/// </summary>
        public static List<LdapValueParsed> ParseLdapValue(string ldapValue, bool isDn = false)
        {
			// Return empty LdapValueParsed List if input ldapValue string is null or empty.
            if (ldapValue.Length == 0)
            {
                return new List<LdapValueParsed>();
            }

            // Create List to store ParseLdapValue objects parsed from input ldapValue string.
            List<LdapValueParsed> parsedValueResults = new List<LdapValueParsed>();

			// Parse each character in input ldapValue string.
			for (int i = 0; i < ldapValue.Length; i++)
            {
				// Extract next character in remaining ldapValue string.
				char nextChar = ldapValue[i];

				// Initialize current character as a string for default Content and ContentDecoded property values in final LdapValueParsed result.
				// String format required for potential 2-character and 3-character Content values for escaped and hex-encoded parsing scenarios.
				string content = nextChar.ToString();
				string contentDecoded = content;

				// If nextChar does not exist as key in character Dictionary then add mostly empty LdapValueParsed
				// object to parsedValueResults List and continue to next character in for loop.
				if (!charContextDict.ContainsKey(nextChar))
				{
					// Add mostly empty parsed object to result List.
					parsedValueResults.Add(new LdapValueParsed(content, contentDecoded));

					// Continue to next for loop iteration.
					continue;
				}

				// Retrieve nextChar's corresponding object from character Dictionary for additional properties.
				CharContext nextCharObj = charContextDict[nextChar];

				// Transpose properties from nextChar's character object to additional variables to be used in LdapValueParsed constructor at end of current method.
				CharClass contentDecodedClass = nextCharObj.Class;
				CharCase contentDecodedCase = nextCharObj.Case;
				bool isPrintable = nextCharObj.IsPrintable;

				// Set nextChar's contentDecodedFormat to Default unless overridden later in current method.
				LdapValueParsedFormat contentDecodedFormat = LdapValueParsedFormat.Default;

				// Potentially override above Default values if next char is a Protected, Escaped or Hex encoded scenario.
				switch (nextChar)
				{
					case '*':
						// Unescaped wildcard character ('*') is a Protected character.
						contentDecodedFormat = LdapValueParsedFormat.Protected;

						break;
					case '\\':
						// Backslash character ('\') is an EscapedUnknown by default with potential upgrade to EscapedKnown or Hex Format.
						contentDecodedFormat = LdapValueParsedFormat.EscapedUnknown;

                        // Break if nextChar is last character in remaining ldapValue string.
                        if ((i + 1) == ldapValue.Length)
                        {
                            break;
                        }

						// Extract single character immediately following nextChar character.
						char nextChar2 = ldapValue[i + 1];

						// If nextChar2 does not exist as key in character Dictionary then add mostly empty LdapValueParsed
						// object to parsedValueResults List and continue to next character in for loop.
						if (!charContextDict.ContainsKey(nextChar2))
						{
							// Initialize current character as a string for default Content and ContentDecoded property values in final LdapValueParsed result.
							// String format required for potential 2-character and 3-character Content values for escaped and hex-encoded parsing scenarios.

							// Update default Content and ContentDecoded property values with concatenation of first two characters for EscapedUnknown format
							// and increment for loop's iterator by one to avoid double-parsing this look-ahead character.
							content = nextChar.ToString() + nextChar2.ToString();
							contentDecoded = content;
							i++;

							// Add mostly empty parsed object to result List.
							parsedValueResults.Add(new LdapValueParsed(content, contentDecoded));

							// Continue to next for loop iteration.
							continue;
						}

						// Retrieve nextChar2's corresponding object from character Dictionary for additional properties.
						CharContext nextChar2Obj = charContextDict[nextChar2];

                        // If nextChar2 is hex character then process 2-character (or potential 3-character) substring as hex conversion.
                        if (nextChar2Obj.IsHex)
                        {
                            // Since confirmed hex encoding scenario then update content string with next character, set
                            // contentDecoded to the hex-to-char conversion and increment for loop's iterator by one to avoid
                            // double-parsing this single look-ahead character.
                            content = nextChar.ToString() + nextChar2.ToString();
                            contentDecoded = Char.ConvertFromUtf32(Convert.ToInt32(nextChar2.ToString(), 16));
                            i++;

                            // Break if nextChar2 is last character in remaining ldapValue string.
                            if ((i + 1) == ldapValue.Length)
                            {
                                break;
                            }

                            // Extract single character immediately following nextChar2 character.
                            char nextChar3 = ldapValue[i + 1];

                            // If nextChar3 is also a hex character then process 3-character substring as hex conversion.
                            // Otherwise proceed with 2-character substring hex conversion.
                            if (charContextDict.ContainsKey(nextChar3) && charContextDict[nextChar3].IsHex)
                            {
                                // Since confirmed 2-character hex encoding scenario then update content string with second look-ahead character,
                                // set contentDecoded to the hex-to-char conversion and increment for loop's iterator by one more to avoid
                                // double-parsing this second look-ahead character.
                                content += nextChar3.ToString();
                                contentDecoded = Char.ConvertFromUtf32(Convert.ToInt32((nextChar2.ToString() + nextChar3.ToString()), 16));
                                i++;
                            }

                            // If hex-decoded contentDecoded character does not exist as key in character Dictionary then update additional properties with mainly Undefined values.
                            // Otherwise retrieve hex-decoded character's correponsding object from character Dictionary for additional properties.
                            if (!charContextDict.ContainsKey(char.Parse(contentDecoded)))
                            {
                                // Update additional properties for current hex-decoded character.
                                isPrintable = false;
                                contentDecodedFormat = LdapValueParsedFormat.Hex;
                                contentDecodedClass = CharClass.Undefined;
                                contentDecodedCase = CharCase.Undefined;
                            }
                            else
                            {
                                // Retrieve hex-decoded character's corresponding object from character Dictionary for additional properties.
                                CharContext contentDecodedCharObj = charContextDict[char.Parse(contentDecoded)];

                                // Update additional properties for current hex-decoded character.
                                isPrintable = contentDecodedCharObj.IsPrintable;
                                contentDecodedFormat = LdapValueParsedFormat.Hex;
                                contentDecodedClass = contentDecodedCharObj.Class;
                                contentDecodedCase = contentDecodedCharObj.Case;
                            }
                        }
                        else
                        {
                            // If confirmed non-hex single-character escaping scenario then update content string with next single character, set contentDecoded
                            // to escaped character and increment for loop's iterator by one to avoid double-parsing this look-ahead character.
                            content = nextChar.ToString() + nextChar2.ToString();
                            contentDecoded = content;
                            i++;

                            // Differentiate between EscapedKnown and EscapedUnknown Format value for non-hex single-character escaping scenario.
                            // EscapedKnown encompasses special characters that require escaping when they appear in DN (Distinguished Name) Attribute Values.
                            // Upgrade default EscapedUnknown Format to EscapedKnown if these special character scenarios are identified below.
                            // Source: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
                            if (isDn)
                            {
                                // Define special characters that require escaping in specific DN (Distinguished Name) Attribute Value scenarios.
                                char[] ldapDnCharsToEscape = new char[] { ',', '\\', '+', '<', '>', ';', '"', '=', '/' };
                                char[] ldapDnCharsToEscapePrefix = new char[] { ' ', '#' };
                                char[] ldapDnCharsToEscapeSuffix = new char[] { ' ' };

                                // Check for presence of above special characters in escaped nextChar2 character.
                                if (ldapDnCharsToEscape.Contains(nextChar2))
                                {
                                    // Main array of special characters must be escaped no matter where they are found in Attribute Value.
                                    contentDecodedFormat = LdapValueParsedFormat.EscapedKnown;
                                }
                                else if ((i == 1) && ldapDnCharsToEscapePrefix.Contains(nextChar2))
                                {
                                    // Leading whitespace or '#' characters must be escaped.
                                    contentDecodedFormat = LdapValueParsedFormat.EscapedKnown;
                                }
                                else if ((i == (ldapValue.Length - 1)) && ldapDnCharsToEscapeSuffix.Contains(nextChar2))
                                {
                                    // Trailing whitespace character must be escaped.
                                    contentDecodedFormat = LdapValueParsedFormat.EscapedKnown;
                                }
                            }
                        }

						break;
				}

				// Create and add final LdapValueParsed object to result List.
				parsedValueResults.Add(new LdapValueParsed(content, contentDecoded, contentDecodedFormat, contentDecodedClass, contentDecodedCase, isPrintable));
			}

			// Return final List of LdapValueParsed objects for input ldapValue string.
			return parsedValueResults;
		}

		/// <summary>
		/// This method returns list of LDAP tokens comprising a single LDAP Filter (given a complete list of LDAP tokens for an entire LDAP SearchFilter and a starting index).
		/// </summary>
        public static List<LdapTokenEnriched> ExtractFilterTokensByIndex(List<LdapTokenEnriched> ldapTokens, int index)
        {
            // Return empty LdapTokenEnriched List if input ldapTokens List is null or empty.
            if (ldapTokens.Count == 0)
            {
                return new List<LdapTokenEnriched>();
            }

            // Starting from input index, walk backward to find starting index of current Filter.
            // This will be either a GroupStart token or the very first token if no GroupStart is present.
            // Instantiate filterStartIndex with lowest possible index value, then override in for loop if GroupStart token is found.
            int filterStartIndex = 0;
            for (int i = index; i >= 0; i--)
            {
                LdapToken tokenLookBehind = ldapTokens[i];

                // Capture index then break out of for loop if GroupStart token is found.
                if (tokenLookBehind.Type == LdapTokenType.GroupStart)
                {
                    filterStartIndex = i;
                    break;
                }
            }

            // Starting from start index identified above, walk forward to find ending index of current Filter.
            // This will be either a GroupEnd token or the very last token if no GroupEnd is present.
            // Instantiate filterEndIndex with highest possible index value, then override in for loop if GroupEnd token is found.
            int filterEndIndex = ldapTokens.Count - 1;
			// Additionally track depth of parenthesis characters (e.g. GroupStart/GroupEnd) to ensure entire filter is accurately
			// extracted while maintaining balanced parentheses.
            int attributeValueParenDepth = 0;
            for (int i = filterStartIndex; i < ldapTokens.Count; i++)
            {
                LdapToken tokenLookAhead = ldapTokens[i];

                // Increment/decrement parenthesis depth if current character is a parenthesis (e.g. GroupStart/GroupEnd).
                switch (tokenLookAhead.Type)
                {
                    case LdapTokenType.GroupStart:
                        attributeValueParenDepth++;
                        break;
                    case LdapTokenType.GroupEnd:
                        attributeValueParenDepth--;
                        break;
                }

				// If current character is a GroupEnd token at the same depth as the starting GroupStart token then update ending filter index and break out of foreach loop.
				if ((tokenLookAhead.Type == LdapTokenType.GroupEnd) && (attributeValueParenDepth == 0))
                {
                    filterEndIndex = i;
                    break;
                }
            }

            // Extract and return copy of all Filter tokens as a List based on indices extracted above.
            return ldapTokens.GetRange(filterStartIndex, ((filterEndIndex - filterStartIndex) + 1));
        }

		/// <summary>
		/// This method returns list of LDAP tokens comprising a single LDAP Filter (given a complete list of LDAP tokens for an entire LDAP SearchFilter and a starting LDAP token).
		/// </summary>
        public static List<LdapTokenEnriched> ExtractFilterTokensByToken(List<LdapTokenEnriched> ldapTokens, LdapTokenEnriched ldapToken)
        {
            // Return empty LdapTokenEnriched List if input ldapTokens List is null or empty.
            if (ldapTokens.Count == 0)
            {
                return new List<LdapTokenEnriched>();
            }

			// Traverse input ldapTokens List to determine index of input ldapToken.
            int index = -1;
            for (int i = 0; i < ldapTokens.Count; i++)
            {
				// Capture index then break out of for loop if input ldapToken is found in input ldapTokens List.
                if (ldapTokens[i].Start == ldapToken.Start)
                {
					index = i;
                    break;
                }
            }

			// Return empty LdapTokenEnriched List if input ldapToken is not found in input ldapTokens List.
			if (index == -1)
            {
                return new List<LdapTokenEnriched>();
            }

			// Extract and return copy of all Filter tokens as a List based on starting index extracted above.
            return ExtractFilterTokensByIndex(ldapTokens, index);
        }

		/// <summary>
		/// This method extracts next LDAP token string from input remaining LDAP SearchFilter, specifically focusing on maintaining balanced parentheses in extracted value.
		/// </summary>
		public static string ExtractBalancedParenthesis(string ldapSearchFilter, int subFilterParenDepth = 0)
        {
            string extractedTokenContent = null;

			// Extract next parsed token from input LDAP SearchFilter by traversing it character-by-character
			// while tracking depth of balanced parentheses.
            string ldapSearchFilterEscapesRemoved = ldapSearchFilter.Replace(@"\\", "__").Replace(@"\(", "__").Replace(@"\)", "__");

			// Create StringBuilder object expecting to hold up to the remaining length of current ldapSearchFilterEscapesRemoved value.
			StringBuilder sbAttributeValue = new StringBuilder(null, ldapSearchFilterEscapesRemoved.Length);

			foreach (char curChar in ldapSearchFilterEscapesRemoved)
			{
				// If closing parenthesis and not currently nested parenthesis depth then break out of foreach loop without including closing parenthesis GroupEnd token (it will be retrieved in next step).
				if ((curChar == ')') && (subFilterParenDepth == 0))
				{
					break;
				}

				// Increment/decrement parenthesis depth if current character is a parenthesis.
				switch (curChar)
				{
					case '(':
						subFilterParenDepth++;
						break;
					case ')':
						subFilterParenDepth--;
						break;
				}

				// Append current character to StringBuilder.
				sbAttributeValue.Append(curChar);
			}

			// Assemble current token content string from StringBuilder.
			extractedTokenContent = ldapSearchFilter.Substring(0, sbAttributeValue.ToString().Length);

			// Return extracted token content.
            return extractedTokenContent;
        }

		/// <summary>
		/// This method returns list of LDAP Attribute Value tokens with RDN SubType parsed from input Attribute Value with DNString format.
		/// </summary>
        public static List<LdapToken> TokenizeRdn(string ldapAttributeValue, int ldapSearchFilterIndex = 0, int ldapSearchFilterDepth = 0)
        {
            // Return empty LdapToken List if input ldapAttributeValue string is null or empty.
            if (ldapAttributeValue.Length == 0)
			{
                return new List<LdapToken>();
            }

            // Create List to store RDN LdapTokens parsed from input ldapAttributeValue string.
            List<LdapToken> tokenResults = new List<LdapToken>();

            // Sanitize RDN to facilitate more efficient splitting on control characters.
            // This removes the need for current method to handle escape and/or hex-encoded
            // control character identification (and double quote encapsulation scenario) for
            // simplified and more efficient RDN parsing.
            string ldapAttributeValueSanitized = SanitizeRdn(ldapAttributeValue);

            // Define Boolean to capture if any sanitization occurred in above method invocation.
			bool isSanitized = ldapAttributeValue != ldapAttributeValueSanitized ? true : false;

            // Track index of input LDAP Attribute Value for extracting substrings from original
            // input based on indices attained from above sanitized LDAP Attribute Value.
            int ldapAttributeValueIndex = 0;

            // Parse current input object into array of RDNs (relative distinguished names)
            // by splitting on unescaped commas in sanitized LDAP Attribute Value.
            string[] ldapAttributeValueSanitizedList = ldapAttributeValueSanitized.Split(',');

			// Iterate over eached RDN and further parse RDN SubType tokens.
            for (int i = 0; i < ldapAttributeValueSanitizedList.Count(); i++)
            {
                // Append comma to current sanitized RDN since it is removed via above Split.
                // Logic at end of foreach loop will exclude final CommaDelimiter from being tokenized.
                string ldapRdnSanitized = ldapAttributeValueSanitizedList[i] + ",";

                // Split current sanitized RDN on ComparisonOperator ("=" is only eligible
				// ComparisonOperator for RDNs) to produce two concatenated substrings,
				// Attribute + ComparisonOperator and Value + CommaDelimiter, which will be
                // further parsed later in this method.
				// RDNs do not support ExtensibleMatchFilter so that logic is not required.
                string ldapRdnSanitizedAttributeAndComparisonOperator;
                string ldapRdnSanitizedValueAndCommaDelimiter;

                // Extract concatenated substrings Attribute + ComparisonOperator and
				// Value + CommaDelimiter (if they exist) from current sanitized RDN, retrieving
				// unsanitized values from original input LDAP Attribute Value later in this method.
                int ldapRdnComparisonOperatorIndex = ldapRdnSanitized.IndexOf("=");
                if (ldapRdnComparisonOperatorIndex == -1)
                {
                    // No ComparisonOperator found in current sanitized RDN.
                    // Treat current sanitized RDN as an RDN Attribute Value + CommaDelimiter.
                    ldapRdnSanitizedAttributeAndComparisonOperator = "";
					ldapRdnSanitizedValueAndCommaDelimiter = ldapRdnSanitized;
                }
                else
                {
                    ldapRdnSanitizedAttributeAndComparisonOperator = ldapRdnSanitized.Substring(0, (ldapRdnComparisonOperatorIndex + 1));
                    ldapRdnSanitizedValueAndCommaDelimiter = ldapRdnSanitized.Substring(ldapRdnSanitizedAttributeAndComparisonOperator.Length);
                }

                // Extract concatenated Attribute and ComparisonOperator substrings (if they exist)
				// from current sanitized RDN, retrieving unsanitized values from original input
				// LDAP Attribute Value.
                if (ldapRdnSanitizedAttributeAndComparisonOperator.Length > 0)
                {
                    // Determine length of ComparisonOperator: 1 by default and 3 if hex-encoded
					// control character (e.g. '\3D' or '\3d').
                    // .EndsWith and .LastIndexOf methods do not calculate null characters present
					// in ldapRdnSanitizedControlCharHexPrefix, so using .Contains method instead.
                    int ldapRdnComparisonOperatorLength = (isSanitized == true) && ldapRdnSanitizedAttributeAndComparisonOperator.Contains($"{ldapRdnSanitizedControlCharHexPrefix}=") ? 3 : 1;

                    // Determine length of Attribute.
                    int ldapRdnAttributeLength = ldapRdnSanitizedAttributeAndComparisonOperator.Length - ldapRdnComparisonOperatorLength;

                    // Extract Attribute and ComparisonOperator from current sanitized RDN.
                    string ldapRdnSanitizedAttribute = ldapRdnSanitized.Substring(0, ldapRdnAttributeLength);
                    string ldapRdnSanitizedComparisonOperator = ldapRdnSanitized.Substring(ldapRdnSanitizedAttribute.Length, ldapRdnComparisonOperatorLength);

					// Create temporary string variable to iteratively hold each next parsed token.
                    string nextTokenContent;

                    // Extract Attribute token, handling potential Whitespace token(s) before
					// and/or after Attribute token.
                    if (ldapRdnSanitizedAttribute.Length > 0)
                    {
                        // Handle if next parsed token is potential Whitespace before RDN Attribute.
                        // Skip whitespace parsing if entire RDN Attribute is only composed of
						// whitespace (non-sensical but syntactically acceptable).
                        nextTokenContent = ldapRdnSanitizedAttribute.Substring(0, (ldapRdnSanitizedAttribute.Length - ldapRdnSanitizedAttribute.TrimStart(' ').Length));
                        if (nextTokenContent.Length > 0 && ldapRdnSanitizedAttribute.TrimStart(' ').Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }

                        // Handle if next parsed token is RDN Attribute.
                        nextTokenContent = ldapRdnSanitizedAttribute.Trim(' ');
                        if (nextTokenContent.Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Attribute, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }

                        // Handle if next parsed token is potential Whitespace after RDN Attribute.
                        nextTokenContent = ldapRdnSanitizedAttribute.Substring(ldapRdnSanitizedAttribute.TrimEnd(' ').Length);
                        if (nextTokenContent.Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }
                    }

                    // Extract ComparisonOperator token.
                    nextTokenContent = ldapRdnSanitizedComparisonOperator;
                    if (nextTokenContent.Length > 0)
					{
                        // Extract unsanitized version of current token from original input
						// LDAP Attribute Value.
                        nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                        // Add extracted token to result List.
                        tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.ComparisonOperator, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                        // Increase current LDAP SearchFilter index.
                        ldapAttributeValueIndex += nextTokenContent.Length;
                    }
                }

                // Extract Attribute Value and CommaDelimiter (if they exist) from current sanitized
                // RDN, retrieving unsanitized values from original input LDAP Attribute Value.
                if (ldapRdnSanitizedValueAndCommaDelimiter.Length > 0)
                {
                    // Determine length of CommaDelimiter: 1 by default and 3 if hex-encoded
					// control character (e.g. '\2C' or '\2c').
                    // .EndsWith and .LastIndexOf methods do not calculate null characters present
					// in ldapRdnSanitizedControlCharHexPrefix, so using .Contains method instead.
                    int ldapRdnCommaDelimiterLength = (isSanitized == true) && ldapRdnSanitizedValueAndCommaDelimiter.Contains($"{ldapRdnSanitizedControlCharHexPrefix},") ? 3 : 1;

                    // Determine length of Attribute Value.
                    int ldapRdnValueLength = ldapRdnSanitizedValueAndCommaDelimiter.Length - ldapRdnCommaDelimiterLength;

                    // Extract Attribute Value and CommaDelimiter from current sanitized RDN.
                    string ldapRdnSanitizedValue = ldapRdnSanitizedValueAndCommaDelimiter.Substring(0, ldapRdnValueLength);
                    string ldapRdnSanitizedCommaDelimiter = ldapRdnSanitizedValueAndCommaDelimiter.Substring(ldapRdnSanitizedValue.Length);

					// Create temporary string variable to iteratively hold each next parsed token.
                    string nextTokenContent;

                    // Extract Attribute Value token, handling potential Whitespace token(s) before
					// and/or after Attribute Value token.
                    if (ldapRdnSanitizedValue.Length > 0)
                    {
                        // Handle if next parsed token is potential Whitespace before RDN Attribute Value.
                        // Skip whitespace parsing if entire RDN Attribute Value is only composed of
						// whitespace (non-sensical but syntactically acceptable).
                        nextTokenContent = ldapRdnSanitizedValue.Substring(0, (ldapRdnSanitizedValue.Length - ldapRdnSanitizedValue.TrimStart(' ').Length));
                        if (nextTokenContent.Length > 0 && ldapRdnSanitizedValue.TrimStart(' ').Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }

                        // Handle if next parsed token is RDN Attribute Value.
                        nextTokenContent = ldapRdnSanitizedValue.Trim(' ');
                        if (nextTokenContent.Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Value, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }

                        // Handle if next parsed token is potential Whitespace after RDN Attribute Value.
                        nextTokenContent = ldapRdnSanitizedValue.Substring(ldapRdnSanitizedValue.TrimEnd(' ').Length);
                        if (nextTokenContent.Length > 0)
                        {
                            // Extract unsanitized version of current token from original input
							// LDAP Attribute Value.
                            nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                            // Increase current LDAP SearchFilter index.
                            ldapAttributeValueIndex += nextTokenContent.Length;
                        }
                    }

                    // Extract CommaDelimiter token unless last iteration, skipping CommaDelimiter
					// manually added at beginning of current method for parsing consistency.
                    nextTokenContent = ldapRdnSanitizedCommaDelimiter;
                    if ((nextTokenContent.Length > 0) && (i < (ldapAttributeValueSanitizedList.Count() - 1)))
					{
                        // Extract unsanitized version of current token from original input
						// LDAP Attribute Value.
                        nextTokenContent = ldapAttributeValue.Substring(ldapAttributeValueIndex, nextTokenContent.Length);

                        // Add extracted token to result List.
                        tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.CommaDelimiter, LdapTokenSubType.RDN, (ldapSearchFilterIndex + ldapAttributeValueIndex), ldapSearchFilterDepth));

                        // Increase current LDAP SearchFilter index.
                        ldapAttributeValueIndex += nextTokenContent.Length;
                    }
                }
            }

			// Return List of parsed LdapTokens with RDN SubType
            return tokenResults;
        }

		/// <summary>
		/// This method returns list of LDAP tokens parsed from an entire LDAP SearchFilter.
		/// </summary>
        public static List<LdapToken> Tokenize(string ldapSearchFilter)
        {
            // Return empty LdapToken List if input ldapSearchFilter string is null or empty.
            if (ldapSearchFilter.Length == 0)
            {
                return new List<LdapToken>();
            }

			// Create Dictionary to track index of last instance of subset of LdapToken types to
			// enable more performant lookups and to avoid costly manual look-behinds for updating
			// Depth and SubType values.
            Dictionary<LdapTokenType, int> lastLdapTokenIndexDict = new Dictionary<LdapTokenType, int>()
            {
                { LdapTokenType.GroupStart, -1 },
                { LdapTokenType.GroupEnd, -1 },
                { LdapTokenType.BooleanOperator, -1 },
                { LdapTokenType.Whitespace, -1 }
            };

            // Create List to store LdapTokens parsed from input ldapSearchFilter string.
            List<LdapToken> tokenResults = new List<LdapToken>();

            // Track input string index and ongoing depth (for GroupStart and GroupEnd parenthesis
			// nesting) throughout parsing.
            int ldapSearchFilterIndex = 0;
            int ldapSearchFilterDepth = -1;

            // Track last ldapSearchFilter value to break if no parsing occurs in any given while
			// loop iteration below.
            string lastLdapSearchFilter = null;

            // Continue parsing until no more input string remains (or until an iteration yields
			// no parsed change to avoid infinite loops).
            while ((ldapSearchFilter.Length > 0) && (ldapSearchFilter != lastLdapSearchFilter))
            {
				// Update lastLdapSearchFilter with result from previous while loop iteration.
                lastLdapSearchFilter = ldapSearchFilter;

                // Extract next character (as both char and string) in remaining LDAP SearchFilter.
                char nextChar = ldapSearchFilter[0];
                string nextTokenContent = nextChar.ToString();

				// Create new undefined LdapTokenType to be updated in below switch block based
				// on identified type of next parsed LDAP token.
                LdapTokenType nextTokenType = LdapTokenType.Undefined;

				// Based on next character extracted from remaining LDAP SearchFilter, extract
				// next LDAP token and identify its corresponding type.
                switch (nextChar)
                {
                    case char curChar when ldapTokenTypeLeadingCharDict[LdapTokenType.GroupStart].Contains(curChar):
                        {
                            // Set LdapTokenType for extracted token.
                            nextTokenType = LdapTokenType.GroupStart;

                            // Increment current depth since GroupStart token (opening parenthesis).
                            ldapSearchFilterDepth++;

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

							// Update Dictionary with extracted token's index in tokenResults List.
							lastLdapTokenIndexDict[nextTokenType] = tokenResults.Count - 1;

                            // Remove extracted token from remaining LDAP SearchFilter and increase
							// current index.
                            ldapSearchFilter = ldapSearchFilter.Substring(nextTokenContent.Length);
                            ldapSearchFilterIndex += nextTokenContent.Length;

                            // If GroupStart token immediately follows a BooleanOperator token
                            // (allowing potential intermediate Whitespace token), then
                            // BooleanOperator token's Depth should inherit GroupStart token's Depth
							// (along with intermediate Whitespace token if present).
                            // BooleanOperators occuring inside a Filter (as opposed to a FilterList)
                            // will not be adjusted since they precede an Attribute token
                            // (allowing potential intermediate Whitespace token).
							if (lastLdapTokenIndexDict[LdapTokenType.BooleanOperator] > -1)
							{
								if (lastLdapTokenIndexDict[LdapTokenType.BooleanOperator] == tokenResults.Count - 2)
								{
									// Update preceding BooleanOperator token's Depth to match
									// current GroupStart token's Depth.
									tokenResults[lastLdapTokenIndexDict[LdapTokenType.BooleanOperator]].Depth = ldapSearchFilterDepth;
								}

								if (
									lastLdapTokenIndexDict[LdapTokenType.BooleanOperator] == tokenResults.Count - 3 &&
									lastLdapTokenIndexDict[LdapTokenType.Whitespace] == tokenResults.Count - 2
								)
								{
									// Update preceding BooleanOperator and intermediate Whitespace
									// token's Depth to match current GroupStart token's Depth.
									tokenResults[lastLdapTokenIndexDict[LdapTokenType.BooleanOperator]].Depth = ldapSearchFilterDepth;
									tokenResults[lastLdapTokenIndexDict[LdapTokenType.Whitespace]].Depth = ldapSearchFilterDepth;
								}
							}

                            break;
                        }
                    case char curChar when ldapTokenTypeLeadingCharDict[LdapTokenType.GroupEnd].Contains(curChar):
                        {
							// Output error message if current depth falls below 0.
							if (ldapSearchFilterDepth < 0)
							{
								Console.ForegroundColor = ConsoleColor.Red;
								Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - Invalid LDAP SearchFilter. Negative depth ({ldapSearchFilterDepth}) beginning at index {ldapSearchFilterIndex}");
								Console.ResetColor();
							}

                            // Set LdapTokenType for extracted token.
                            nextTokenType = LdapTokenType.GroupEnd;

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

							// Update Dictionary with extracted token's index in tokenResults List.
							lastLdapTokenIndexDict[nextTokenType] = tokenResults.Count - 1;

                            // Decrement current depth since GroupEnd token (closing parenthesis).
                            ldapSearchFilterDepth--;

                            // Remove extracted token from remaining LDAP SearchFilter and
							// increase current index.
                            ldapSearchFilter = ldapSearchFilter.Substring(nextTokenContent.Length);
                            ldapSearchFilterIndex += nextTokenContent.Length;

                            break;
                        }
                    case char curChar when ldapTokenTypeLeadingCharDict[LdapTokenType.Whitespace].Contains(curChar):
                        {
                            // Set LdapTokenType for extracted token.
                            nextTokenType = LdapTokenType.Whitespace;

                            // Next token is whitespace, so extract all leading whitespace as single token.
							// Since hex-encoded representation of whitespace ('\20') is not supported
							// in this location, perform non-Regex leading whitespace extraction
							// technique via .Substring for performance purposes.
							nextTokenContent = ldapSearchFilter.Substring(0, (ldapSearchFilter.Length - ldapSearchFilter.TrimStart(' ').Length));

							// Add extracted token to result List.
							tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

							// Update Dictionary with extracted token's index in tokenResults List.
							lastLdapTokenIndexDict[nextTokenType] = tokenResults.Count - 1;

							// Remove extracted token from remaining LDAP SearchFilter and increase
							// current index.
							ldapSearchFilter = ldapSearchFilter.Substring(nextTokenContent.Length);
							ldapSearchFilterIndex += nextTokenContent.Length;

							// If Whitespace token immediately follows a GroupEnd token,
							// then Whitespace token's Depth should inherit preceding token's Depth.
							if (
								lastLdapTokenIndexDict[LdapTokenType.GroupEnd] > -1 &&
								lastLdapTokenIndexDict[LdapTokenType.GroupEnd] == tokenResults.Count - 2
							)
							{
								// Update current Whitespace token's Depth to match preceding GroupEnd
								// token's Depth.
								tokenResults[lastLdapTokenIndexDict[nextTokenType]].Depth = tokenResults[lastLdapTokenIndexDict[LdapTokenType.GroupEnd]].Depth;
							}

                            break;
                        }
                    case char curChar when ldapTokenTypeLeadingCharDict[LdapTokenType.BooleanOperator].Contains(curChar):
                        {
                            // Set LdapTokenType for extracted token.
                            nextTokenType = LdapTokenType.BooleanOperator;

                            // Add extracted token to result List.
                            tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

							// Update Dictionary with extracted token's index in tokenResults List.
							lastLdapTokenIndexDict[LdapTokenType.BooleanOperator] = tokenResults.Count - 1;

                            // Remove extracted token from remaining LDAP SearchFilter and increase
							// current index.
                            ldapSearchFilter = ldapSearchFilter.Substring(nextTokenContent.Length);
                            ldapSearchFilterIndex += nextTokenContent.Length;

                            break;
                        }
                    default:
                        {
                            // Current ldapSearchFilter substring does not match above control
							// character cases; therefore, it is the beginning of a Filter.
                            // The next tokens to extract will be Attribute, (optional)
							// ExtensibleMatchFilter, ComparisonOperator and Value.
                            // Additionally extract potential Whitespace tokens interspersed in
							// Filter between token types listed above.

                            // Create temporary string placeholders for Attribute, (optional)
							// ExtensibleMatchFilter, ComparisonOperator and Attribute Value
							// LdapTokens which will be parsed next.
                            string nextTokenContentAttribute = null;
                            string nextTokenContentExtensibleMatchFilter = null;
                            string nextTokenContentComparisonOperator = null;
							string nextTokenContentAttributeValue = null;

							// Extract next Filter content (not including final GroupEnd), properly
							// tracking balanced parenthesis depth.
							string nextFilterContent = LdapParser.ExtractBalancedParenthesis(ldapSearchFilter);

							// Track starting index in LDAP SearchFilter for extracted Filter above
							// to be used for accurate removal of all parsed Filter tokens from
							// remaining LDAP SearchFilter at end of current method.
							int ldapFilterStartingIndex = ldapSearchFilterIndex;

                            // Extract index of ComparisonOperator anchor character in Filter.
                            int comparisonOperatorIndex = nextFilterContent.IndexOf(ldapTokenTypeLeadingCharDict[LdapTokenType.ComparisonOperator][0]);

							// If no ComparisonOperator is found or begins with '<==>' then check
							// for server-side LDAP logging shorthand format
							// ExtensibleMatchFilter+ComparisonOperator shorthand syntax.
							// If this shorthand syntax is found then normalize nextFilterContent
							// and update ldapSearchFilter so remainder of function will parse
							// normalized values correctly.
							// E.g. (options&1) => (options:1.2.840.113556.1.4.803:=1)
							// E.g. (userAccountControl|67117056) => (userAccountControl:1.2.840.113556.1.4.804:= 67117056)
							// E.g. (distinguishedName<==>CN=dbo,CN=Users,DC=contoso,DC=local) => (distinguishedName:1.2.840.113556.1.4.1941:=CN=dbo,CN=Users,DC=contoso,DC=local)
							if (
								comparisonOperatorIndex == -1 ||
								nextFilterContent.Substring(comparisonOperatorIndex - 1).StartsWith("<==>")
							)
							{
								// Perform Regex evaluation against current Filter content to determine
								// if server-side LDAP logging shorthand format scenario is present,
								// extracting shorthand ExtensibleMatchFilter and Value tokens via Regex
								// capture groups.
								Match match = ldapComparisonOperatorAndValueServerLogShorthandFormat.Match(nextFilterContent);
								if (match.Success)
								{
									// Update ExtensibleMatchFilter string to Regex match capture group for ExtensibleMatchFilter.
									string nextTokenContentExtensibleMatchFilterOrig = match.Groups["extensible_match_filter"].ToString();

									// Normalize shorthand ExtensibleMatchFilter format to valid ExtensibleMatchFilter.
									switch (nextTokenContentExtensibleMatchFilterOrig)
									{
										case "&":
											nextTokenContentExtensibleMatchFilter = ":1.2.840.113556.1.4.803:";

											break;
										case "|":
											nextTokenContentExtensibleMatchFilter = ":1.2.840.113556.1.4.804:";

											break;
										case "<==>":
											nextTokenContentExtensibleMatchFilter = ":1.2.840.113556.1.4.1941:";

											break;
										default:
											// Output error message if unhandled shorthand ExtensibleMatchFilter encountered.
											Console.ForegroundColor = ConsoleColor.Red;
											Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - Server-side LDAP logging shorthand format scenario encountered unhandled shorthand ExtensibleMatchFilter. Expected shorthand ExtensibleMatchFilters include: '&', '|', '<==>'");
											Console.ResetColor();

											// Set next ExtensibleMatchFilter to be current unhandled shorthand syntax encapsulated with required colon characters.
											nextTokenContentExtensibleMatchFilter = $":{nextTokenContentExtensibleMatchFilterOrig}:";

											break;
									}

									// Update Attribute Value string to Regex match capture group for Attribute Value.
									nextTokenContentAttributeValue = match.Groups["attribute_value"].ToString();

									// Extract Attribute from current Filter based on index of original extracted ExtensibleMatchFilter.
									nextTokenContentAttribute = nextFilterContent.Substring(0, nextFilterContent.IndexOf(nextTokenContentExtensibleMatchFilterOrig));

									// Set ComparisonOperator to be '=' since it it the only option for implied shorthand ExtensibleMatchFilters.
									nextTokenContentComparisonOperator = "=";

									// Normalize nextFilterContent and update ldapSearchFilter with this normalized nextFilterContent.
									string nextFilterContentOrig = nextFilterContent;
									nextFilterContent = nextTokenContentAttribute + nextTokenContentExtensibleMatchFilter + nextTokenContentComparisonOperator + nextTokenContentAttributeValue;
									ldapSearchFilter = nextFilterContent + ldapSearchFilter.Substring(nextFilterContentOrig.Length);

									// Extract new index of ComparisonOperator anchor character in normalized Filter.
									comparisonOperatorIndex = nextFilterContent.IndexOf(ldapTokenTypeLeadingCharDict[LdapTokenType.ComparisonOperator][0]);
								}
							}

							// If undefined Attribute or ExtensibleMatchFilter is found in LDAP
							// SearcFilter then server-side LDAP logging will log the individual
							// Filter as '(UNDEFINED)'.
							// If this shorthand syntax is found then normalize nextFilterContent
							// and update ldapSearchFilter so remainder of function will parse
							// normalized values correctly.
							// E.g. (UNDEFINED) => (UNDEFINED=UNDEFINED)
							if (nextFilterContent == "UNDEFINED")
							{
								// Set Attribute, ComparisonOperator and Attribute Values to be
								// 'UNDEFINED' placeholder values so Filter is valid.
								nextTokenContentAttribute = "UNDEFINED";
								nextTokenContentComparisonOperator = "=";
								nextTokenContentAttributeValue = "UNDEFINED";

								// Normalize nextFilterContent and update ldapSearchFilter with this normalized nextFilterContent.
								string nextFilterContentOrig = nextFilterContent;
								nextFilterContent = nextTokenContentAttribute + nextTokenContentComparisonOperator + nextTokenContentAttributeValue;
								ldapSearchFilter = nextFilterContent + ldapSearchFilter.Substring(nextFilterContentOrig.Length);

								// Extract new index of ComparisonOperator anchor character in normalized Filter.
								comparisonOperatorIndex = nextFilterContent.IndexOf(ldapTokenTypeLeadingCharDict[LdapTokenType.ComparisonOperator][0]);
							}

                            // Continue with further parsing of Attribute and (optional)
							// ExtensibleMatchFilter LdapTokens as well as ComparisonOperator and
							// Value LdapTokens (if ComparisonOperator index populated above).
                            if (comparisonOperatorIndex == -1)
							{
								// Output error message if current Filter does not contain a
								// ComparisonOperator token.
								Console.ForegroundColor = ConsoleColor.Red;
								Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - Invalid LDAP SearchFilter. No ComparisonOperator found in current filter beginning at index {ldapSearchFilterIndex}: {nextFilterContent}");
								Console.ResetColor();

								// Extract Attribute from current Filter.
								// Set entire Filter as Attribute (with potential for
								// ExtensibleMatchFilter extraction below).
								nextTokenContentAttribute = nextFilterContent;

								// Extract index of next ExtensibleMatchFilter anchor character
								// (if it exists) in extracted Attribute.
								int extensibleMatchFilterIndex = nextTokenContentAttribute.IndexOf(ldapTokenTypeLeadingCharDict[LdapTokenType.ExtensibleMatchFilter][0]);

								// Separate ExtensibleMatchFilter (if present) from extracted Attribute.
								if ((extensibleMatchFilterIndex > 0) && nextTokenContentAttribute.EndsWith(ldapTokenTypeLeadingCharDict[LdapTokenType.ExtensibleMatchFilter][0]))
								{
									nextTokenContentExtensibleMatchFilter = nextTokenContentAttribute.Substring(extensibleMatchFilterIndex);
									nextTokenContentAttribute = nextTokenContentAttribute.Substring(0, extensibleMatchFilterIndex);
								}
							}
                            else
							{
								// Extract first and second halves of current Filter.
                                string nextFilterContentFirstHalf = nextFilterContent.Substring(0, comparisonOperatorIndex + 1);
                                string nextFilterContentSecondHalf = nextFilterContent.Substring(nextFilterContentFirstHalf.Length);

								// Define array of characters that lead the supported 2-character
								// ComparisonOperator values (e.g. '>=', '<=' or '~=') for identifying
								// starting index of ComparisonOperator in current Filter substring.
                                char[] ldapTokenComparisonOperator_CharPrefixValArr = new char[] { '~', '<', '>' };

								// Decrement ComparisonOperator index if 2-character ComparisonOperator
								// value (e.g. '>=', '<=' or '~=') identified in current Filter substring.
                                if ((nextFilterContentFirstHalf.Length > 2) && ldapTokenComparisonOperator_CharPrefixValArr.Contains(nextFilterContentFirstHalf[nextFilterContentFirstHalf.Length - 2]))
								{
									comparisonOperatorIndex--;
								}

								// Extract Attribute and ComparisonOperator from first half of current Filter.
								nextTokenContentAttribute = nextFilterContentFirstHalf.Substring(0, comparisonOperatorIndex);
								nextTokenContentComparisonOperator = nextFilterContentFirstHalf.Substring(comparisonOperatorIndex);

								// Extract index of next ExtensibleMatchFilter anchor character
								// (if it exists) in extracted Attribute.
								int extensibleMatchFilterIndex = nextTokenContentAttribute.IndexOf(ldapTokenTypeLeadingCharDict[LdapTokenType.ExtensibleMatchFilter][0]);

								// Separate ExtensibleMatchFilter (if present) from extracted Attribute.
								if ((extensibleMatchFilterIndex > 0) && nextTokenContentAttribute.EndsWith(ldapTokenTypeLeadingCharDict[LdapTokenType.ExtensibleMatchFilter][0]))
								{
									nextTokenContentExtensibleMatchFilter = nextTokenContentAttribute.Substring(extensibleMatchFilterIndex);
									nextTokenContentAttribute = nextTokenContentAttribute.Substring(0, extensibleMatchFilterIndex);
								}

								// Extract Attribute Value from second half of current Filter.
								nextTokenContentAttributeValue = nextFilterContentSecondHalf;
							}

							// Process Attribute token extracted previously.

							// Set content and LdapTokenType for extracted token.
							nextTokenContent = nextTokenContentAttribute;
							nextTokenType = LdapTokenType.Attribute;
							if (nextTokenContent != null)
							{
								// Remove any potential trailing Whitespace from extracted token.
								nextTokenContent = nextTokenContent.TrimEnd(' ');

								// Add extracted token to result List.
								tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

								// Remove extracted token from current Filter and increase current index.
								nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
								ldapSearchFilterIndex += nextTokenContent.Length;

								// Break if no remaining Filter.
								if (nextFilterContent.Length == 0)
								{
									// Remove extracted Filter from remaining LDAP SearchFilter.
									ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

									break;
								}

								// Extract next character in current Filter for continued parsing.
								nextChar = nextFilterContent[0];

								// Handle if next parsed token is potential Whitespace.
								nextTokenContent = nextFilterContent;
								nextTokenType = LdapTokenType.Whitespace;
								if (ldapTokenTypeLeadingCharDict[nextTokenType].Contains(nextChar))
								{
									// Since hex-encoded representation of whitespace ('\20') is
									// not supported in this location, perform non-Regex leading
									// whitespace extraction technique via .Substring for
									// performance purposes.
									nextTokenContent = nextTokenContent.Substring(0, (nextTokenContent.Length - nextTokenContent.TrimStart(' ').Length));

									// Add extracted token to result List.
									tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

									// Remove extracted token from current Filter and increase current index.
									nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
									ldapSearchFilterIndex += nextTokenContent.Length;

									// Break if no remaining Filter.
									if (nextFilterContent.Length == 0)
									{
										// Remove extracted Filter from remaining LDAP SearchFilter.
										ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

										break;
									}

									// Extract next character in current Filter for continued parsing.
									nextChar = nextFilterContent[0];
								}
							}

							// Process potential ExtensibleMatchFilter token extracted previously.

							// Set content and LdapTokenType for extracted token.
							nextTokenContent = nextTokenContentExtensibleMatchFilter;
							nextTokenType = LdapTokenType.ExtensibleMatchFilter;
							if (nextTokenContent != null)
							{
								// Based on how ExtensibleMatchFilter token was parsed (due to
								// its very definition), no trailing Whitespace will exist in
								// current token.
								// If any Whitespace existed between an "ExtensibleMatchFilter"
								// and ComparisonOperator then the "ExtensibleMatchFilter" would
								// technically be part of the Attribute instead.
								// E.g. (name:caseExactMatch: =dbo) has no ExtensibleMatchFilter,
								// but the Attribute is name:caseExactMatch:

								// Add extracted token to result List.
								tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

								// Remove extracted token from current Filter and increase current index.
								nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
								ldapSearchFilterIndex += nextTokenContent.Length;

								// Break if no remaining Filter.
								if (nextFilterContent.Length == 0)
								{
									// Remove extracted Filter from remaining LDAP SearchFilter.
									ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

									break;
								}

								// Extract next character in current Filter for continued parsing.
								nextChar = nextFilterContent[0];
							}

							// Process ComparisonOperator token extracted previously.

							// Set content and LdapTokenType for extracted token.
							nextTokenContent = nextTokenContentComparisonOperator;
							nextTokenType = LdapTokenType.ComparisonOperator;
							if (nextTokenContent != null)
							{
								// Based on how ComparisonOperator token was parsed, no trailing
								// Whitespace will exist in current token.
								// Any Whitespace existing before Attribute Value token will be
								// handled more intricately later in current method to handle
								// more complex scenarios involving hex-encoded representation of
								// Whitespace ('\20').

								// Add extracted token to result List.
								tokenResults.Add(new LdapToken(nextTokenContent, nextTokenType, ldapSearchFilterIndex, ldapSearchFilterDepth));

								// Remove extracted token from current Filter and increase current index.
								nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
								ldapSearchFilterIndex += nextTokenContent.Length;

								// Break if no remaining Filter.
								if (nextFilterContent.Length == 0)
								{
									// Remove extracted Filter from remaining LDAP SearchFilter.
									ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

									break;
								}

								// Extract next character in current Filter for continued parsing.
								nextChar = nextFilterContent[0];
							}

							// Process Attribute Value token extracted previously.

							// Set content and LdapTokenType for extracted token.
							nextTokenContent = nextTokenContentAttributeValue;
							nextTokenType = LdapTokenType.Value;
							if (nextTokenContent != null)
							{
								// Extract potential Whitespace (if it exists) after ComparisonOperator,
								// including if hex-encoded representation (e.g. '\20').
								if (ldapTokenTypeLeadingCharDict[LdapTokenType.Whitespace].Contains(nextChar) || (nextChar == '\\' && nextTokenContent.StartsWith(@"\20")))
								{
									// Set current token content string to be all leading Whitespace
									// characters (including if hex-encoded '\20').
									nextTokenContent = nextTokenContent.Substring(0, (nextTokenContent.Length - nextTokenContent.Replace(@"\20", "   ").TrimStart(' ').Length));

									// Add extracted token to result List.
									tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, ldapSearchFilterIndex, ldapSearchFilterDepth));

									// Remove extracted token from current Filter and increase current index.
									nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
									ldapSearchFilterIndex += nextTokenContent.Length;

									// Break if no remaining Filter.
									if (nextFilterContent.Length == 0)
									{
										// Remove extracted Filter from remaining LDAP SearchFilter.
										ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

										break;
									}

									// Extract next character in current Filter for continued parsing.
									nextChar = nextFilterContent[0];

									// Set content to be remaining current Filter.
									nextTokenContent = nextFilterContent;
								}

								// Remove any potential trailing whitespace (if it exists) after
								// Attribute Value (including if hex-encoded representation, e.g. '\20')
								// so it can be parsed separately as a Whitespace token.
								if (nextTokenContent.EndsWith(" ") || nextTokenContent.EndsWith(@"\20"))
								{
									nextTokenContent = nextTokenContent.Substring(0, nextTokenContent.Replace(@"\20", "   ").TrimEnd(' ').Length);
								}

								// Attribute Value successfully extracted into nextTokenContent string.
								// If Value is RDN (Relative Distinguished Name) then parse accordingly
								// and add array of RDN SubType LdapTokens to result List.
								// Otherwise add extracted token to result List.
								if (IsRdn(nextTokenContent))
								{
									// Parse RDN value to add to TokenList property of new token below.
									List<LdapToken> rdnTokens = TokenizeRdn(nextTokenContent, ldapSearchFilterIndex, ldapSearchFilterDepth);

									// Add extracted token to result List.
									tokenResults.Add(new LdapToken(nextTokenContent, rdnTokens, LdapTokenType.Value, ldapSearchFilterIndex, ldapSearchFilterDepth));
								}
								else
								{
									// Add extracted token to result List.
									tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Value, ldapSearchFilterIndex, ldapSearchFilterDepth));
								}

								// Remove extracted token from current Filter and increase current index.
								nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
								ldapSearchFilterIndex += nextTokenContent.Length;

								// Break if no remaining Filter.
								if (nextFilterContent.Length == 0)
								{
									// Remove extracted Filter from remaining LDAP SearchFilter.
									ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

									break;
								}

								// Extract next character in current Filter for continued parsing.
								nextChar = nextFilterContent[0];

								// Set content to be remaining current Filter.
								nextTokenContent = nextFilterContent;

								// Extract potential Whitespace (if it exists) after Attribute Value,
								// including if hex-encoded representation (e.g. '\20').
								if (ldapTokenTypeLeadingCharDict[LdapTokenType.Whitespace].Contains(nextChar) || (nextChar == '\\' && nextTokenContent.StartsWith(@"\20")))
								{
									// Set current token content string to be all leading Whitespace
									// characters (including if hex-encoded '\20').
									nextTokenContent = nextTokenContent.Substring(0, (nextTokenContent.Length - nextTokenContent.Replace(@"\20", "   ").TrimStart(' ').Length));

									// Add extracted token to result List.
									tokenResults.Add(new LdapToken(nextTokenContent, LdapTokenType.Whitespace, ldapSearchFilterIndex, ldapSearchFilterDepth));

									// Remove extracted token from current Filter and increase current index.
									nextFilterContent = nextFilterContent.Substring(nextTokenContent.Length);
									ldapSearchFilterIndex += nextTokenContent.Length;
								}
							}

							// Remove extracted Filter from remaining LDAP SearchFilter.
							ldapSearchFilter = ldapSearchFilter.Substring(ldapSearchFilterIndex - ldapFilterStartingIndex);

                            break;
                        }
                }
            }

			// Output error message if last while loop iteration did not parse any of ldapSearchFilter.
			if (ldapSearchFilter == lastLdapSearchFilter)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - No parsing occurred in last iteration for remaining LDAP SearchFilter beginning at index {ldapSearchFilterIndex}: {ldapSearchFilter}");
				Console.ResetColor();
			}

			// If tokens were extracted and first token is Whitespace then update token's Depth
			// property to 0 since it is initialized to -1.
			if (tokenResults.Count > 0 && tokenResults[0].Depth == -1 && tokenResults[0].Type == LdapTokenType.Whitespace)
			{
				tokenResults[0].Depth = 0;
			}

            // Return List of parsed LdapTokens.
            return tokenResults;
        }

		/// <summary>
		/// This method returns list of enriched LDAP tokens based on input list of LDAP tokens parsed from an entire LDAP SearchFilter.
		/// </summary>
        public static List<LdapTokenEnriched> ToTokenEnriched(List<LdapToken> ldapTokens)
        {
            // Return empty LdapTokenEnriched List if input ldapTokens List is null or empty.
            if (ldapTokens.Count == 0)
            {
                return new List<LdapTokenEnriched>();
            }

            // Convert input List from List<LdapToken> to List<LdapTokenEnriched> so additional
			// properties are present to be populated in current method.
            List<LdapTokenEnriched> ldapTokensEnriched = ldapTokens.ConvertAll(token => new LdapTokenEnriched(token));

            // Create List to store BooleanOperator tokens for tracking additional context for
			// Filter/FilterList groupings.
            // This tracking is most important for implicit BooleanOperator application in the midst
			// of unnecessary GroupStart/GroupEnd encapsulation as well as for detection opportunities
			// based on BooleanOperator distance and bigrams per Filter/FilterList grouping.
            // Using List instead of Stack since traversing entire List in reverse (without popping
			// values) is required for splitting current BooleanOperator values into separate Lists
			// to differentiate between FilterList and Filter scopes.
            List<LdapTokenEnriched> ldapTokenBooleanOperatorList = new List<LdapTokenEnriched>();

			// Create additional List to track BooleanOperator tokens that directly precede any
			// given Filter.
			// This must be a separate List since above List will have Filter-scope BooleanOperators
			// removed when they are applied to a Filter (as opposed to a FilterList) branch.
			// However, for the purposes of tracking maximum permitted BooleanOperators per given
			// Filter these Filter-scope removals still need to be factored into total count.
			List<LdapTokenEnriched> ldapTokenBooleanOperatorHistoricalList = new List<LdapTokenEnriched>();

            // Iterate over all input LDAP tokens and add TypeBefore and TypeAfter property values
			// to each token based on its neighboring token Type property values.
            for (int i = 0; i < ldapTokensEnriched.Count; i++)
            {
                LdapTokenEnriched token = ldapTokensEnriched[i];

                // Set TypeBefore and TypeAfter property values based on current token's neighboring
				// token Type property value(s).
                // Handle bookend token scenarios separately.
                if (i == 0 || i == (ldapTokensEnriched.Count - 1))
                {
					// Handle multi-token and single-token bookend scenarios.
					if (ldapTokensEnriched.Count > 1)
                    {
                        // For first token assign TypeBefore to null and TypeAfter to the next
						// token's Type property value.
                        ldapTokensEnriched[0].TypeBefore = null;
                        ldapTokensEnriched[0].TypeAfter = ldapTokensEnriched[1].Type;

                        // For last token assign TypeAfter to null and TypeBefore to the previous
						// token's Type property value.
                        ldapTokensEnriched[ldapTokensEnriched.Count - 1].TypeBefore = ldapTokensEnriched[ldapTokensEnriched.Count - 2].Type;
                        ldapTokensEnriched[ldapTokensEnriched.Count - 1].TypeAfter = null;
                    }
                    else if (ldapTokensEnriched.Count == 1)
                    {
                        // If only one token is present then assign TypeBefore and TypeAfter
						// properties to null.
                        ldapTokensEnriched[0].TypeBefore = null;
                        ldapTokensEnriched[0].TypeAfter = null;
                    }
                }
                else
                {
					// Not bookend scenario, so set TypeBefore and TypeAfter property values based
					// on current token's neighboring token Type property values.
                    token.TypeBefore = ldapTokens[i - 1].Type;
                    token.TypeAfter = ldapTokens[i + 1].Type;
                }

				// Overwrite Value token's TokenList property if current Format is not a
				// DN (Distinguished Name).
				// This avoids non-DN string Attribute Value tokens that technically pass the
				// validation for a DN but can cause FPs for detections targeting non-standard
				// RDN (Relative Distinguished Name) elements, for example.
				//     E.g. DN: (&(distinguishedName=DC=WINDOMAIN,DC=LOCAL)(name=dbo))
				//     E.g. non-DN: (&(accountType=DC=WINDOMAIN,DC=LOCAL)(name=dbo))
				// This step is performed only for LdapTokenEnriched instead of initial LdapToken
				// since Context object(s) containing Format property (used below) are only added
				// for LdapTokenEnriched and not for LdapToken.
				if (token.TokenList.Count > 0 && token.Type == LdapTokenType.Value && !(token.Format == LdapTokenFormat.DNString || token.Format == LdapTokenFormat.DNWithBinary))
				{
					// Overwrite Value token's TokenList property with empty list so not treated as
					// parsed DN (Distinguished Name).
					token.TokenList = new List<LdapTokenEnriched>();
				}

                // If RDN values are present (stored in TokenList) enumerate them separately to
				// add TypeBefore and TypeAfter property values, specifically connecting bookend
				// RDN tokens to neighboring non-RDN token Type property values.
                if (token.TokenList.Count > 0 && token.Type == LdapTokenType.Value)
                {
                    List<LdapTokenEnriched> rdnTokens = token.TokenList;

					// Handle multi-token and single-token RDN bookend scenarios separately so
					// remaining for loop can more efficiently process TypeBefore/TypeAfter
					// assignment without needing to check for bookend scenarios each iteration.
                    if (rdnTokens.Count > 1)
                    {
                        // If more than one token is present then handle bookend scenarios with
						// on-RDN tokens.

                        // For first token assign TypeBefore to previous non-RDN token's Type
                        // property value and TypeAfter to next RDN token's Type property value.
                        rdnTokens[0].TypeBefore = ldapTokens[i - 1].Type;
                        rdnTokens[0].TypeAfter = rdnTokens[1].Type;

                        // For last token assign TypeBefore to previous RDN token's Type property
                        // value and TypeAfter to next non-RDN token's (if it exists) Type property value.
                        rdnTokens[rdnTokens.Count - 1].TypeBefore = rdnTokens[rdnTokens.Count - 2].Type;
                        if (i < ldapTokens.Count - 1)
                        {
                            rdnTokens[rdnTokens.Count - 1].TypeAfter = ldapTokens[i + 1].Type;
                        }
                        else
                        {
                            // Set RDN token's TypeAfter to null if it is the last token in the
							// LDAP token List.
                            rdnTokens[rdnTokens.Count - 1].TypeAfter = null;
                        }
                    }
                    else if (rdnTokens.Count == 1)
                    {
                        // If only one RDN token is present then assign TypeBefore to the previous
						// non-RDN token's Type property value and TypeAfter to the next non-RDN
						// token's (if it exists) Type property value.
                        rdnTokens[0].TypeBefore = ldapTokens[i - 1].Type;
                        if (i < ldapTokens.Count - 1)
                        {
                            rdnTokens[0].TypeAfter = ldapTokens[i + 1].Type;
                        }
                        else
                        {
                            // Set RDN token's TypeAfter to null if it is the last token in the
							// LDAP token List.
                            rdnTokens[0].TypeAfter = null;
                        }
                    }

                    // Iterate over all remaining RDN tokens (excluding first and potential last
					// tokens handled in above bookend scenarios).
                    for (int j = 1; j < rdnTokens.Count - 1; j++)
                    {
                        // Convert LdapToken to LdapTokenEnriched to provide access to additional
						// enrichment properties.
                        LdapTokenEnriched rdnToken = rdnTokens[j];

                        rdnToken.TypeBefore = rdnTokens[j - 1].Type;
                        rdnToken.TypeAfter = rdnTokens[j + 1].Type;
                    }
                }

                // Instantiate ScopeSyntax and ScopeApplication variables as null.
                // They will be defined in certain scenarios in below switch block.
                Nullable<LdapTokenScope> scopeSyntax = null;
                Nullable<LdapTokenScope> scopeApplication = null;
                switch (token.Type)
                {
                    case LdapTokenType.GroupStart:
                        // Determine if current GroupStart token is part of a Filter or FilterList.

                        // Step forward to see if current GroupStart token is followed first by an
						// Attribute token or another GroupStart token (excluding potential
						// intermediate Whitespace and/or BooleanOperator tokens).
                        // Since i is index of current GroupStart token, start with i + 1 and walk
						// forward until finding first token that is not Whitespace or BooleanOperator.
                        for (int j = i + 1; j < ldapTokens.Count; j++)
                        {
                            LdapToken tokenLookAhead = ldapTokens[j];

                            if (tokenLookAhead.Type != LdapTokenType.Whitespace && tokenLookAhead.Type != LdapTokenType.BooleanOperator)
                            {
                                switch (tokenLookAhead.Type)
                                {
                                    case LdapTokenType.GroupStart:
                                        scopeSyntax = LdapTokenScope.FilterList;
                                        scopeApplication = LdapTokenScope.FilterList;

                                        break;
                                    case LdapTokenType.Attribute:
                                        scopeSyntax = LdapTokenScope.Filter;
                                        scopeApplication = LdapTokenScope.Filter;

                                        break;
                                    default:
										// Output error message if unhandled look-ahead TokenType encountered.
										Console.ForegroundColor = ConsoleColor.Red;
										Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - LdapTokenScope look-ahead for GroupStart token encountered unhandled TokenType {tokenLookAhead.Type} at index {j}. Expected look-ahead TokenTypes following GroupStart token include: Whitespace, BooleanOperator, Attribute, GroupStart");
										Console.ResetColor();

                                        break;
                                }

                                // Break out of look-ahead analysis since scenario has been determined.
                                break;
                            }
                        }

                        // Update current GroupStart token's ScopeSyntax and ScopeApplication properties
						// with values set in above switch block.
                        token.ScopeSyntax = scopeSyntax;
                        token.ScopeApplication = scopeApplication;

                        // Create List to track potential BooleanOperators with ScopeApplication of
						// Filter currently stored in context tracking BooleanOperator List.
                        List<LdapTokenEnriched> ldapTokenBooleanOperatorListForCurrentFilter = new List<LdapTokenEnriched>();

                        // If current GroupStart token is the beginning of a Filter then perform
						// look-ahead via ExtractFilterTokensByIndex method to collect all tokens in
						// current Filter so potential Filter-scope BooleanOperator can be added to
						// context tracking List.
                        // Then perform potential delineation between trailing non-FilterList
						// BooleanOperators in current tracking List.
                        if (token.ScopeApplication == LdapTokenScope.Filter)
                        {
							// Create ldapAttributeContext to track Attribute's Context object in
							// below for loop to more accurately determine proceeding Attribute Value
							// format information.
							LdapAttributeContext ldapAttributeContext = new LdapAttributeContext();

							// Extract List of all tokens in current Filter context for current
							// GroupStart token at index i.
							List<LdapTokenEnriched> filterTokenList = ExtractFilterTokensByIndex(ldapTokensEnriched, i);

							// Iterate over above filterTokenList and extract potential BooleanOperator
							// token to add to current context tracking List.
							for (int k = 0; k < filterTokenList.Count; k++)
							{
								LdapTokenEnriched filterToken = filterTokenList[k];

								// Add potential BooleanOperator to context tracking List.
								switch (filterToken.Type)
								{
									case LdapTokenType.BooleanOperator:
										// Update current BooleanOperator token's enriched properties
										// (ScopeSyntax, ScopeApplication, TypeBefore, TypeAfter and
										// Guid) since current lookahead occurs before BooleanOperator
										// is traversed.
										// Therefore below logic is duplicated from main BooleanOperator
										// case statement later in method.
										// Search for comment tag DUPLICATED_BOOLEAN_OPERATOR_SCOPE_CALCULATION
										// to find later instance of this logic.

                                        // BooleanOperator token is immediately inside a Filter, so its
										// ScopeSyntax is Filter.
                                        scopeSyntax = LdapTokenScope.Filter;

                                        // ScopeApplication for '!' is Filter, but for '&' and '|' the
										// ScopeApplication is NA (Not Applicable) since technically
										// this scenario has no effect on the LDAP query result.
                                        if (filterToken.Content == "!")
                                        {
                                            scopeApplication = LdapTokenScope.Filter;
                                        }
                                        else
                                        {
                                            scopeApplication = LdapTokenScope.NA;
                                        }

										// Update current BooleanOperator token's ScopeSyntax and
										// ScopeApplication properties with values set above.
										filterToken.ScopeSyntax = scopeSyntax;
										filterToken.ScopeApplication = scopeApplication;

										// Update current BooleanOperator token's TypeBefore and
										// TypeAfter properties.
										filterToken.TypeBefore = (k - 1) >= 0 ? filterTokenList[k - 1].Type : LdapTokenType.Undefined;
										filterToken.TypeAfter = (k + 1) < filterTokenList.Count ? filterTokenList[k + 1].Type : LdapTokenType.Undefined;

										// Generate new GUID for BooleanOperator and add to context
										// tracking List and separate historical tracking List.
										filterToken.Guid = Guid.NewGuid();
										ldapTokenBooleanOperatorList.Add(filterToken);
										ldapTokenBooleanOperatorHistoricalList.Add(filterToken);

										break;
									case LdapTokenType.Attribute:
										// Capture current Filter's Attribute Context object to
										// extract ValueFormat property for current Filter's
										// Attribute Value in next case statement.
										ldapAttributeContext = filterToken.Context.Attribute;

										break;
									case LdapTokenType.Value:
										// Update Attribute Value's Context object with ValueFormat
										// information extracted from Attribute's Context object.
										filterToken.Context.Value.Format = ldapAttributeContext.ValueFormat;
										filterToken.Format = ldapAttributeContext.ValueFormat;

										// If Attribute Value format is Bitwise and Value is parseable
										// as a long (e.g. will skip if '*' presence value) then
										// parse/convert Value to long and continue with bitwise addend
										// extraction for Value Context object.
										if ((filterToken.Format == LdapTokenFormat.Bitwise) && long.TryParse(filterToken.ContentDecoded, out long bitwiseVal))
										{
											// Extract list of addend(s) comprising current bitwise Value.
											filterToken.Context.Value.BitwiseAddend = ToBitAddend(bitwiseVal);

											// Populate Dict in Value Context object for each addend
											// extracted above.
											foreach (double bit in filterToken.Context.Value.BitwiseAddend)
											{
												filterToken.Context.Value.BitwiseDict[bit] = true;
											}

											// If bitwise Value is between 2^31 and 2^32 then wrap to
											// negative value per Microsoft Active Directory rules since
											// this negative number is what the LDAP server logs when it
											// executes the query for this larger-than-2^31 value.
											// Source (Footnote 17): https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
											// This wrapped negative value will be set in LdapToken's
											// ContentDecoded property for detection and/or feature
											// extraction purposes.
											if (bitwiseVal >= (long)System.Math.Pow(2, 31) && bitwiseVal < (long)System.Math.Pow(2, 32))
											{
												filterToken.ContentDecoded = (bitwiseVal - (long)System.Math.Pow(2, 32)).ToString();
											}
										}

										// If RDN values are present (stored in TokenList) enumerate
										// them separately to add Format property to RDN Attribute
										// Value's Context object.
										if (filterToken.TokenList.Count > 0)
										{
											List<LdapTokenEnriched> rdnTokens = filterToken.TokenList;

											// Create ldapAttributeContext to track RDN Attribute's
											// Context object in below foreach loop to more accurately
											// determine proceeding RDN Attribute Value's format information.
											LdapAttributeContext ldapRdnAttributeContext = new LdapAttributeContext();

											// Iterate over all RDN tokens, transposing RDN Attribute's
											// Context object's ValueFormat property to RDN Attribute
											// Value's Context object's Format property.
											foreach (LdapTokenEnriched rdnToken in rdnTokens)
											{
												switch (rdnToken.Type)
												{
													case LdapTokenType.Attribute:
														// Capture current RDN Attribute's Context object
														// to extract ValueFormat property for later RDN
														// Attribute Value in next case statement.
														ldapRdnAttributeContext = rdnToken.Context.Attribute;

														break;
													case LdapTokenType.Value:
														// Update RDN Attribute Value's Context object
														// with ValueFormat information extracted from
														// RDN Attribute's Context object.
														rdnToken.Context.Value.Format = ldapRdnAttributeContext.ValueFormat;
														rdnToken.Format = ldapRdnAttributeContext.ValueFormat;

														break;
												}
											}
										}

										break;
								}
							}

							// Pop trailing non-FilterList BooleanOperator value(s) from primary context
							// tracking List after prepending to new BooleanOperator Filter List.
							// This is because non-FilterList ScopeApplication BooleanOperators only
							// apply to the first BooleanOperator or Filter in their direct path.
							while ((ldapTokenBooleanOperatorList.Count > 0) && (ldapTokenBooleanOperatorList[ldapTokenBooleanOperatorList.Count - 1].ScopeApplication != LdapTokenScope.FilterList))
							{
								LdapTokenEnriched trailingTokenBooleanOperator = ldapTokenBooleanOperatorList[ldapTokenBooleanOperatorList.Count - 1];

								// Prepend trailing BooleanOperator to ScopeApplication Filter List.
								ldapTokenBooleanOperatorListForCurrentFilter.Insert(0, trailingTokenBooleanOperator);

								// Pop trailing BooleanOperator from primary context tracking List.
								ldapTokenBooleanOperatorList.RemoveAt(ldapTokenBooleanOperatorList.Count - 1);

								// Do not decrement total BooleanOperator count based on Filter-scope values.
							}
                        }

						// Consolidate current BooleanOperator context into LdapBooleanOperatorContext
						// object and add to current GroupStart token.
						token.Context.BooleanOperator = new LdapBooleanOperatorContext(token.Depth, ldapTokenBooleanOperatorList, ldapTokenBooleanOperatorListForCurrentFilter, ldapTokenBooleanOperatorHistoricalList.Count);

						// If current GroupStart token is the beginning of a Filter then pop potential
						// trailing Filter-scope BooleanOperator(s) added to Filter by look-ahead via
						// ExtractFilterTokensByIndex method earlier in method since context captured
						// in LdapBooleanOperatorContext creation above.
						if (token.ScopeApplication == LdapTokenScope.Filter)
						{
							while ((ldapTokenBooleanOperatorHistoricalList.Count > 0) && (ldapTokenBooleanOperatorHistoricalList[ldapTokenBooleanOperatorHistoricalList.Count - 1].ScopeSyntax == LdapTokenScope.Filter))
							{
								// Pop trailing Filter-scope BooleanOperator(s) from historical
								// BooleanOperator List.
								ldapTokenBooleanOperatorHistoricalList.RemoveAt(ldapTokenBooleanOperatorHistoricalList.Count - 1);
							}
						}

						// Determine if negation BooleanOperator ('!') traversal is affecting
						// current Filter.
						switch (token.ScopeApplication)
						{
							case LdapTokenScope.FilterList:
								// Convert FilterList BooleanOperator token List to simple string for
								// easier trailing negation BooleanOperator ('!') analysis below.
								string contextFilterListBooleanOperatorTokenListStr = token.Context.BooleanOperator.FilterListBooleanOperatorTokenList == null ? "" : string.Concat(token.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Where(token => token.ScopeSyntax == LdapTokenScope.FilterList).Select(token => token.Content));

								// Negation BooleanOperator traversal exists for current FilterList
								// LdapBranch if its BooleanOperator context contains an odd number
								// of FilterList-syntax negation BooleanOperator ('!') LdapTokens
								// since an even number cancels out the logical negation.
								if (
									token.Context.BooleanOperator.FilterListBooleanOperator != null &&
									(contextFilterListBooleanOperatorTokenListStr.Length - contextFilterListBooleanOperatorTokenListStr.TrimEnd('!').Length) % 2 == 1
								)
								{
									token.Context.BooleanOperator.NegationBooleanOperatorTraversal = true;
								}

								break;
							case LdapTokenScope.Filter:
								// Convert Filter BooleanOperator token List to simple string for
								// easier leading negation BooleanOperator ('!') analysis below.
								string contextFilterBooleanOperatorTokenListStr = token.Context.BooleanOperator.FilterBooleanOperatorTokenList == null ? "" : string.Concat(token.Context.BooleanOperator.FilterBooleanOperatorTokenList.Where(token => token.ScopeSyntax == LdapTokenScope.FilterList).Select(token => token.Content));

								// Negation BooleanOperator traversal exists for current Filter
								// LdapBranch if its BooleanOperator context contains an odd number
								// of Filter-syntax negation BooleanOperator ('!') LdapTokens since
								// an even number cancels out the logical negation.
								if (
									token.Context.BooleanOperator.FilterBooleanOperatorTokenList != null &&
									(contextFilterBooleanOperatorTokenListStr.Length - contextFilterBooleanOperatorTokenListStr.TrimStart('!').Length) % 2 == 1
								)
								{
									token.Context.BooleanOperator.NegationBooleanOperatorTraversal = true;
								}

								break;
						}

                        break;
                    case LdapTokenType.GroupEnd:
                        // Pop BooleanOperator value(s) from context tracking List where
						// BooleanOperator Depth is greater than current GroupEnd token's Depth.
                        // While loop is required instead of if block when BooleanOperator is
						// applied at both Filter and FilterList levels at the same depth.
                        // E.g. (&(Name=Domain*)(!Name=Domain Guests))
                        while ((ldapTokenBooleanOperatorList.Count > 0) && (ldapTokenBooleanOperatorList[ldapTokenBooleanOperatorList.Count - 1].Depth > token.Depth))
                        {
                            ldapTokenBooleanOperatorList.RemoveAt(ldapTokenBooleanOperatorList.Count - 1);
                        }

                        // Pop trailing non-FilterList BooleanOperator value(s) from context
						// tracking List.
						// This is because non-FilterList ScopeApplication BooleanOperators only
						// apply to the first BooleanOperator or Filter in their direct path.
						while ((ldapTokenBooleanOperatorList.Count > 0) && (ldapTokenBooleanOperatorList[ldapTokenBooleanOperatorList.Count - 1].ScopeApplication != LdapTokenScope.FilterList))
                        {
							// Pop trailing BooleanOperator from primary context tracking List.
                            ldapTokenBooleanOperatorList.RemoveAt(ldapTokenBooleanOperatorList.Count - 1);
                        }

						// Repeat above depth-based step for Historical BooleanOperator List since
						// it can intentionally become out of sync with primary BooleanOperator List
						// since ScopeSyntax BooleanOperator handling in next step is handled
						// differently for each List.
						// Do not pop any trailing non-FilterList BooleanOperators from historical
						// BooleanOperator List since they still apply toward total permitted
						// BooleanOperator count for later Filter LdapBranches.
						while ((ldapTokenBooleanOperatorHistoricalList.Count > 0) && (ldapTokenBooleanOperatorHistoricalList[ldapTokenBooleanOperatorHistoricalList.Count - 1].Depth > token.Depth))
						{
							// Pop trailing BooleanOperator from historical BooleanOperator List.
                            ldapTokenBooleanOperatorHistoricalList.RemoveAt(ldapTokenBooleanOperatorHistoricalList.Count - 1);
                        }

                        // Determine if current GroupEnd token is part of a Filter or FilterList.

                        // Step backward to see if current GroupEnd token is preceded first by a
						// filter's Value token or another GroupEnd token (excluding potential
						// intermediate Whitespace tokens).
                        // Since i is index of current GroupEnd token, start with i - 1 and walk
						// backward until finding first token that is not Whitespace.
                        for (int j = i - 1; j >= 0; j--)
                        {
                            LdapToken tokenLookBehind = ldapTokens[j];

                            if (tokenLookBehind.Type != LdapTokenType.Whitespace)
                            {
                                switch (tokenLookBehind.Type)
                                {
                                    case LdapTokenType.GroupEnd:
                                        scopeSyntax = LdapTokenScope.FilterList;
                                        scopeApplication = LdapTokenScope.FilterList;

                                        break;
                                    case LdapTokenType.Value:
                                        scopeSyntax = LdapTokenScope.Filter;
                                        scopeApplication = LdapTokenScope.Filter;

                                        break;
                                    default:
										// Output error message if unhandled look-behind TokenType encountered.
										Console.ForegroundColor = ConsoleColor.Red;
										Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - LdapTokenScope look-behind for GroupEnd token encountered unhandled TokenType {tokenLookBehind.Type} at index {j}. Expected look-behind TokenTypes preceding GroupEnd token include: Whitespace, Value, GroupEnd");
										Console.ResetColor();

                                        break;
                                }

                                // Break out of look-behind analysis since scenario has been determined.
                                break;
                            }
                        }

                        // Update current GroupEnd token's ScopeSyntax and ScopeApplication properties
						// with values set in above switch block.
                        token.ScopeSyntax = scopeSyntax;
                        token.ScopeApplication = scopeApplication;

                        break;
                    case LdapTokenType.BooleanOperator:
                        // Determine if current BooleanOperator token is part of a Filter or FilterList.

						// Filter-scope logic below is duplicated in GroupStart case statement earlier
						// in method since potential Filter-scope BooleanOperator extracted in lookahead
						// logic for calculating GroupStart token's Context.BooleanOperator property
						// before reaching current case statement.

                        /*
                         * According to the formal definition of LDAP SearchFilter syntax as defined
						 * in RFC 2254 (https://datatracker.ietf.org/doc/html/rfc2254), BooleanOperators
						 * '&' and '|' apply to FilterLists and '!' applies to Filters.
                         *     <and> ::= '&' <filterlist>
                         *     <or> ::= '|' <filterlist>
                         *     <not> ::= '!' <filter>
                         *
                         * In practice, however, these BooleanOperator tokens can be applied to several
						 * more token types both in syntax and application.
                         * Determine if current BooleanOperator's Scope is 'Filter' or 'FilterList' both
						 * for ScopeSyntax (what the scope should be based on syntax) and ScopeApplication
						 * (what the scope is in application regardless of syntax).
                         * ScopeSyntax and ScopeApplication can differ, and this difference is a
						 * unique signal for threat hunting purposes.
                         * Of notable interest is when a BooleanOperator has a ScopeApplication
						 * of 'NA' or 'BooleanOperator'.
                         *
                         * '&' and '|' BooleanOperators almost always have a ScopeSyntax of 'FilterList'
						 * and ScopeApplication of 'FilterList'.
                         * However, these BooleanOperators can be present inside a Filter (ScopeSyntax
						 * value of 'Filter' and ScopeApplication value of 'NA') even though this has
						 * no effect on the LDAP query result.
                         * E.g. of ScopeSyntax = 'FilterList' and ScopeApplication = 'FilterList'
                         *      (&(Name=sabi)(sAMAccountName=sabi))
                         * E.g. of ScopeSyntax = 'Filter' and ScopeApplication = 'NA'
                         *      (&Name=sabi)
                         *
                         * '!' BooleanOperator almost always has a ScopeApplication of 'Filter' even
						 * if ScopeSyntax is 'FilterList', but BooleanOperator's ScopeApplication can
						 * also be 'BooleanOperator'.
                         * E.g. of ScopeSyntax = 'FilterList' and ScopeApplication = 'Filter'
                         *      (&(!(Name=sabi))(sAMAccountName=sabi))
                         * E.g. of ScopeSyntax = 'Filter' and ScopeApplication = 'Filter'
                         *      (&(!Name=sabi)(|sAMAccountName=sabi))
                         * E.g. of ScopeSyntax = 'FilterList' and ScopeApplication = 'BooleanOperator'
                         *      (!(&(Name=sabi)(sAMAccountName=sabi)))
                         */

                        // Step forward to see if current BooleanOperator token applies directly to
						// an Attribute or to another BooleanOperator token.
                        // Since i is index of current BooleanOperator token, start with i + 1 and
						// walk forward until finding first token that is not Whitespace or GroupStart.
                        for (int j = i + 1; j < ldapTokens.Count; j++)
                        {
                            LdapToken tokenLookAhead = ldapTokens[j];

                            if (tokenLookAhead.Type != LdapTokenType.Whitespace)
                            {
                                switch (tokenLookAhead.Type)
                                {
                                    case LdapTokenType.GroupStart:
                                        if (token.Content != "!")
                                        {
                                            scopeSyntax = LdapTokenScope.FilterList;
                                            scopeApplication = LdapTokenScope.FilterList;
                                        }
                                        else
                                        {
                                            // Since BooleanOperator is '!' continue look-ahead in
											// additional sub-loop to determine if this BooleanOperator
                                            // directly applies to a Filter or another BooleanOperator
											// to determine the correct ScopeApplication value.
                                            for (int k = j + 1; k < ldapTokens.Count; k++)
                                            {
                                                if (ldapTokens[k].Type != LdapTokenType.Whitespace && ldapTokens[k].Type != LdapTokenType.GroupStart)
                                                {
                                                    switch (ldapTokens[k].Type)
                                                    {
                                                        case LdapTokenType.BooleanOperator:
                                                            scopeSyntax = LdapTokenScope.FilterList;
                                                            scopeApplication = LdapTokenScope.BooleanOperator;

                                                            break;
                                                        case LdapTokenType.Attribute:
                                                            scopeSyntax = LdapTokenScope.FilterList;
                                                            scopeApplication = LdapTokenScope.Filter;

                                                            break;
														default:
															// Output error message if unhandled double-
															// look-ahead TokenType encountered.
															Console.ForegroundColor = ConsoleColor.Red;
															Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - LdapTokenScope double-look-ahead for BooleanOperator->GroupStart token combination encountered unhandled TokenType {ldapTokens[k].Type} at index {k}. Expected double-look-ahead TokenTypes following BooleanOperator->GroupStart token combination include: Whitespace, GroupStart, BooleanOperator, Attribute");
															Console.ResetColor();

															break;
                                                    }

                                                    // Break out of look-ahead analysis since scenario
													// has been determined.
                                                    break;
                                                }
                                            }
                                        }

                                        break;
                                    case LdapTokenType.Attribute:
										// Below logic is referenced and duplicated in BooleanOperator
										// look-ahead case statement earlier in method.
										// Search for comment tag DUPLICATED_BOOLEAN_OPERATOR_SCOPE_CALCULATION
										// to find earlier instance of this logic.

                                        // BooleanOperator token is immediately inside a Filter, so
										// its ScopeSyntax is Filter.
                                        scopeSyntax = LdapTokenScope.Filter;

                                        // ScopeApplication for '!' is Filter, but for '&' and '|' the
										// ScopeApplication is NA (Not Applicable) since technically
										// this scenario has no effect on the LDAP query result.
                                        if (token.Content == "!")
                                        {
                                            scopeApplication = LdapTokenScope.Filter;
                                        }
                                        else
                                        {
                                            scopeApplication = LdapTokenScope.NA;
                                        }

                                        break;
                                    default:
										// Output error message if unhandled look-ahead TokenType encountered.
										Console.ForegroundColor = ConsoleColor.Red;
										Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::Tokenize - LdapTokenScope look-ahead for BooleanOperator token encountered unhandled TokenType {tokenLookAhead.Type} at index {j}. Expected look-ahead TokenTypes following BooleanOperator token include: Whitespace, Attribute, GroupStart");
										Console.ResetColor();

                                        break;
                                }

                                // Break out of look-ahead analysis since scenario has been determined.
                                break;
                            }
                        }

                        // Update current BooleanOperator token's ScopeSyntax and ScopeApplication
						// properties with values set in above switch block.
                        token.ScopeSyntax = scopeSyntax;
                        token.ScopeApplication = scopeApplication;

                        // Add BooleanOperator to context tracking List unless its scope is Filter
						// since this scenario is already handled in GroupStart switch block via
						// look-ahead extraction of BooleanOperator via ExtractFilterTokensByIndex method.
                        //if (token.ScopeApplication != LdapTokenScope.Filter)
                        if (token.ScopeSyntax == LdapTokenScope.FilterList)
                        {
							// Generate new GUID for BooleanOperator and add to context tracking List
							// and separate historical tracking List.
                            token.Guid = Guid.NewGuid();
                            ldapTokenBooleanOperatorList.Add(token);
							ldapTokenBooleanOperatorHistoricalList.Add(token);
                        }

                        break;
                }
            }

            // Return List of feature-enriched LdapTokens.
            return ldapTokensEnriched;
        }

        // Overloaded method to handle multiple input formats.
        public static List<LdapTokenEnriched> ToTokenEnriched(string ldapSearchFilter)
        {
            // Return List of feature-enriched LdapTokens.
            return LdapParser.ToTokenEnriched(
                    LdapParser.Tokenize(ldapSearchFilter)
                );
        }

		/// <summary>
		/// This method returns list of LDAP Filters (and optional enriched LDAP tokens existing
		/// between filters) which are groupings of enriched LDAP tokens consisting of a bare minimum
		/// of GroupStart + Attribute + ComparisonOperator + AttributeValue + GroupEnd tokens (and
		/// optional BooleanOperator, ComparisonOperator and Whitespace tokens) from input enriched
		/// tokens parsed from an entire LDAP SearchFilter.
		/// </summary>
        public static List<object> ToFilter(List<LdapTokenEnriched> ldapTokens, bool returnFilterOnly = false)
		{
            // Return empty List of objects if input ldapTokens List is null or empty.
            if (ldapTokens.Count == 0)
            {
                return new List<object>();
            }

            // Create List to store merged LdapFilter and LdapTokenEnriched results in current
			// method to return as single List.
            List<object> ldapFilterMergedList = new List<object>();

            // Iterate over all input LdapTokenEnriched objects.
            for (int i = 0; i < ldapTokens.Count; i++)
            {
                LdapTokenEnriched token = ldapTokens[i];

                // Create bool to track if current GroupStart token is the beginning of a Filter
				// as opposed to a FilterList.
                bool isFilter = ((token.Type == LdapTokenType.GroupStart) && (token.ScopeApplication == LdapTokenScope.Filter)) ? true : false;

                // If current GroupStart token is the beginning of a Filter then extract all Filter's
				// tokens and return as LdapFilter object.
                if (isFilter)
                {
                    // Extract List of all tokens in current Filter context for current GroupStart
					// token at index i.
                    List<LdapTokenEnriched> filterTokenList = ExtractFilterTokensByIndex(ldapTokens, i);

                    // Increment for loop index by number of tokens in current Filter extracted
					// above (minus 1 due to for loop iterator).
                    i += filterTokenList.Count - 1;

                    // Create LdapFilter object based on Filter tokens extracted above.
                    LdapFilter ldapFilter = new LdapFilter(filterTokenList);

                    // Add current LdapFilter to ldapFilterMergedList to be returned as a single
					// List at end of method.
                    ldapFilterMergedList.Add(ldapFilter);
                }
                else if (!returnFilterOnly)
                {
                    // Add current LdapTokenEnriched to ldapFilterMergedList to be returned as a
					// single List at end of method.
                    ldapFilterMergedList.Add(token);
                }
            }

            // Return List of merged LdapFilter and LdapTokenEnriched objects.
            return ldapFilterMergedList;
        }

        // Overloaded method to handle multiple input formats.
        public static List<object> ToFilter(List<LdapToken> ldapTokens, bool returnFilterOnly = false)
        {
            // Return List of merged LdapFilter and LdapTokenEnriched objects.
            return LdapParser.ToFilter(
                    LdapParser.ToTokenEnriched(ldapTokens),
					returnFilterOnly
                );
        }

        // Overloaded method to handle multiple input formats.
        public static List<object> ToFilter(string ldapSearchFilter, bool returnFilterOnly = false)
        {
            // Return List of merged LdapFilter and LdapTokenEnriched objects.
            return LdapParser.ToFilter(
                    LdapParser.ToTokenEnriched(
                        LdapParser.Tokenize(ldapSearchFilter)
                    ),
					returnFilterOnly
                );
        }

		/// <summary>
		/// This method returns list of LDAP Filters (excluding optional enriched LDAP tokens existing
		/// between filters) which are groupings of enriched LDAP tokens consisting of a bare minimum
		/// of GroupStart + Attribute + ComparisonOperator + AttributeValue + GroupEnd tokens (and
		/// optional BooleanOperator, ComparisonOperator and Whitespace tokens) from input enriched
		/// tokens parsed from an entire LDAP SearchFilter.
		/// </summary>
        public static List<LdapFilter> ToFilterOnly(List<LdapTokenEnriched> ldapTokens)
        {
            // Return List of only LdapFilter objects, converting List<object> results to List<LdapFilter>.
            return ToFilter(ldapTokens, true).ConvertAll(filter => (LdapFilter)filter);
        }

        // Overloaded method to handle multiple input formats.
        public static List<LdapFilter> ToFilterOnly(List<LdapToken> ldapTokens)
        {
            // Return List of only LdapFilter objects, converting List<object> results to List<LdapFilter>.
            return LdapParser.ToFilterOnly(
                    LdapParser.ToTokenEnriched(ldapTokens)
                );
        }

        // Overloaded method to handle multiple input formats.
        public static List<LdapFilter> ToFilterOnly(string ldapSearchFilter)
        {
            // Return List of only LdapFilter objects, converting List<object> results to List<LdapFilter>.
            return LdapParser.ToFilterOnly(
                    LdapParser.ToTokenEnriched(
                        LdapParser.Tokenize(ldapSearchFilter)
                    )
                );
        }

		/// <summary>
		/// This method returns list of input LDAP Filters and enriched LDAP tokens existing between
		/// filters stored as LDAP branches in a nested parse tree/syntax tree structure containing
		/// entire LDAP SearchFilter.
		/// </summary>
        public static LdapBranch ToBranch(List<object> ldapTokensAndBranchesMerged, LdapBranchType type = LdapBranchType.FilterList, int depth = 0, int index = 0)
        {
            // Return empty LdapBranch if input List of merged LdapTokenEnriched and/or LdapFilter
			// objects is null or empty.
            if (ldapTokensAndBranchesMerged.Count == 0)
            {
                return new LdapBranch();
            }

			// Create new FilterList LdapBranch to store next recursive set of LdapTokenEnriched
			// and/or LdapFilter object(s).
            LdapBranch ldapBranchFilterList = new LdapBranch(type, index, depth);

			// Create StringBuilders to store all Content and ContentDecoded property values for all
			// objects added to newly created LdapBranch above.
			StringBuilder sbLdapBranchContent = new StringBuilder(null);
			StringBuilder sbLdapBranchContentDecoded = new StringBuilder(null);

			// Create int variables to track maximum Depth, maximum BooleanOperator count and maximum
			// logical BooleanOperator count (stored in HistoricalBooleanOperatorCount property in
			// BooleanOperatorContext object) property values for all objects (LdapTokenEnrichend and
			// LdapBranch) added to newly created LdapBranch above.
			int ldapBranchFilterListDepthMax = -1;
			int ldapBranchFilterListBooleanOperatorCountMax = -1;
			int ldapBranchFilterListBooleanOperatorLogicalCountMax = -1;

			// Iterate over each merged LdapTokenEnriched and/or LdapFilter object, beginning with
			// index defined in method's input parameter.
            for (int i = index; i < ldapTokensAndBranchesMerged.Count; i++)
            {
                // Handle separately if current node is LdapFilter versus LdapTokenEnriched.
                if (ldapTokensAndBranchesMerged[i] is LdapFilter)
                {
					// Explicitly cast current object to LdapFilter.
                    LdapFilter ldapFilter = ldapTokensAndBranchesMerged[i] as LdapFilter;

                    // Create new Filter Branch instantiated with current LdapFilter object (set in
					// List<object> for LdapBranch's Branch property).
                    LdapBranch ldapBranchFilter = new LdapBranch(ldapFilter);

					// Append current Filter's Content and ContentDecoded values to respective StringBuilders.
					sbLdapBranchContent.Append(ldapFilter.Content);
					sbLdapBranchContentDecoded.Append(ldapFilter.ContentDecoded);

                    // Append newly created Filter LdapBranch to current LdapBranch.
                    ldapBranchFilterList.Branch.Add(ldapBranchFilter);

					// Update ldapBranchFilterListDepthMax if Filter LdapBranch's DepthMax property
					// value exceeds current ldapBranchFilterListDepthMax value.
					ldapBranchFilterListDepthMax = ldapBranchFilter.DepthMax > ldapBranchFilterListDepthMax ? ldapBranchFilter.DepthMax : ldapBranchFilterListDepthMax;

					// Update ldapBranchFilterListBooleanOperatorCountMax if Filter LdapBranch's
					// BooleanOperatorCountMax property value exceeds current
					// ldapBranchFilterListBooleanOperatorCountMax value.
					ldapBranchFilterListBooleanOperatorCountMax = ldapBranchFilter.BooleanOperatorCountMax > ldapBranchFilterListBooleanOperatorCountMax ? ldapBranchFilter.BooleanOperatorCountMax : ldapBranchFilterListBooleanOperatorCountMax;

					// Update ldapBranchFilterListBooleanOperatorLogicalCountMax if Filter LdapBranch's
					// BooleanOperatorLogicalCountMax property value exceeds current
					// ldapBranchFilterListBooleanOperatorLogicalCountMax value.
					ldapBranchFilterListBooleanOperatorLogicalCountMax = ldapBranchFilter.BooleanOperatorLogicalCountMax > ldapBranchFilterListBooleanOperatorLogicalCountMax ? ldapBranchFilter.BooleanOperatorLogicalCountMax : ldapBranchFilterListBooleanOperatorLogicalCountMax;
                }
                else if (ldapTokensAndBranchesMerged[i] is LdapTokenEnriched)
                {
					// Explicitly cast current object to LdapTokenEnriched.
                    LdapTokenEnriched curLdapToken = ldapTokensAndBranchesMerged[i] as LdapTokenEnriched;

					// Perform separate logic for GroupStart LdapToken, GroupEnd LdapToken and then
					// all other LdapTokens.
                    if (
                        curLdapToken.Type == LdapTokenType.GroupStart &&
                        curLdapToken.ScopeApplication == LdapTokenScope.FilterList
                    )
                    {
						// Since a FilterList-scope GroupStart LdapToken begins a new LdapBranch,
						// increment index for next LdapToken and recursively create new LdapBranch.
						// Recursive LdapBranch will inherit current GroupStart LdapToken's Depth
						// property as seen in constructor invocation below.
						int nextTokenIndex = i + 1;
						LdapBranch recursiveFilterListBranch = ToBranch(ldapTokensAndBranchesMerged, LdapBranchType.FilterList, curLdapToken.Depth, nextTokenIndex);

                        // Prepend current GroupStart LdapToken to above recursive LdapBranch results
						// (GroupEnd LdapToken is appended in recursive method call).
                        recursiveFilterListBranch.Branch.Insert(0, curLdapToken);

						// Prepend GroupStart LdapToken value to current recursively-created
						// FilterList's Content and ContentDecoded properties since it is not
						// present at the time of LdapBranch creation but is manually added above
						// on the tail end of recursion.
						recursiveFilterListBranch.Content = curLdapToken.Content + recursiveFilterListBranch.Content;
						recursiveFilterListBranch.ContentDecoded = curLdapToken.ContentDecoded + recursiveFilterListBranch.ContentDecoded;

						// Update Length property for newly created recursive FilterList LdapBranch
						// since GroupStart LdapToken is prepended above at the tail end of recursion.
						recursiveFilterListBranch.Length = recursiveFilterListBranch.Content.Length;

						// Update Start and Depth properties for newly created recursive FilterList
						// LdapBranch since GroupStart LdapToken is prepended above at the tail end
						// of recursion.
						recursiveFilterListBranch.Start = curLdapToken.Start;
						recursiveFilterListBranch.Depth = curLdapToken.Depth;

						// Copy ContextDict from current FilterList (stored in current GroupStart
						// LdapToken) to newly created FilterList LdapBranch above.
						recursiveFilterListBranch.Context = curLdapToken.Context;

						// Add BooleanOperator string property to recursively created branch by
						// performing lookahead of 1-2 indices looking for LdapTokenEnriched of
						// Type BooleanOperator.
						// The ONLY allowed intermediate object at index i + 1 is an LdapTokenEnriched
						// of Type Whitespace.
						// Any other object (like Filter object) will exit loop to avoid double-depth
						// lookahead issues.
						foreach (int lookaheadTokenIndex in new int[] { i + 1, i + 2 })
						{
							// Break out of loop if current index exceeds List size.
							if (lookaheadTokenIndex >= ldapTokensAndBranchesMerged.Count)
							{
								break;
							}

							// Extract lookahead object as a type object since its true type is not
							// yet known and will be handled in following if blocks via direct casts.
							object lookaheadTokenObject = ldapTokensAndBranchesMerged[lookaheadTokenIndex];

							// Break out of loop if lookahead object is not an LdapTokenEnriched
							// (i.e. it is a Filter object).
							if (!(lookaheadTokenObject is LdapTokenEnriched))
							{
								break;
							}

							// Only LdapTokenEnriched scenario allowed (for which the double lookahead
							// was created) is Whitespace.
							// Problematic scenarios are Filter objects (handled above) or GroupStart
							// objects (handled below).

							// Break out of loop if lookahead object is a GroupStart LdapTokenEnriched.
							if (((LdapTokenEnriched)lookaheadTokenObject).Type == LdapTokenType.GroupStart)
							{
								break;
							}

							// If lookahead object is a BooleanOperator LdapTokenEnriched then set
							// its content in current recursively created LdapBranch's BooleanOperator
							// string property then break out of loop.
							if (((LdapTokenEnriched)lookaheadTokenObject).Type == LdapTokenType.BooleanOperator)
							{
								recursiveFilterListBranch.BooleanOperator = ((LdapTokenEnriched)lookaheadTokenObject).Content;

								break;
							}
						}

                        // Add above recursive LdapBranch results to current LdapBranch.
                        ldapBranchFilterList.Branch.Add(recursiveFilterListBranch);

						// Append current recursively-created FilterList's Content and ContentDecoded
						// values to respective StringBuilders.
						sbLdapBranchContent.Append(recursiveFilterListBranch.Content);
						sbLdapBranchContentDecoded.Append(recursiveFilterListBranch.ContentDecoded);

						// Update ldapBranchFilterListDepthMax if recursive FilterList LdapBranch's
						// DepthMax property value exceeds current ldapBranchFilterListDepthMax value.
						ldapBranchFilterListDepthMax = recursiveFilterListBranch.DepthMax > ldapBranchFilterListDepthMax ? recursiveFilterListBranch.DepthMax : ldapBranchFilterListDepthMax;

						// Update ldapBranchFilterListBooleanOperatorCountMax if recursive FilterList
						// LdapBranch's BooleanOperatorCountMax property value exceeds current
						// ldapBranchFilterListBooleanOperatorCountMax value.
						ldapBranchFilterListBooleanOperatorCountMax = recursiveFilterListBranch.BooleanOperatorCountMax > ldapBranchFilterListBooleanOperatorCountMax ? recursiveFilterListBranch.BooleanOperatorCountMax : ldapBranchFilterListBooleanOperatorCountMax;

						// Update ldapBranchFilterListBooleanOperatorLogicalCountMax if recursive
						// FilterList LdapBranch's BooleanOperatorLogicalCountMax property value
						// exceeds current ldapBranchFilterListBooleanOperatorLogicalCountMax value.
						ldapBranchFilterListBooleanOperatorLogicalCountMax = recursiveFilterListBranch.BooleanOperatorLogicalCountMax > ldapBranchFilterListBooleanOperatorLogicalCountMax ? recursiveFilterListBranch.BooleanOperatorLogicalCountMax : ldapBranchFilterListBooleanOperatorLogicalCountMax;

                        // Advance i index to index of last LdapToken in recursive method call
						// (which should be a GroupEnd LdapToken).
						// This index will be incremented in next for loop iteration.
                        i = recursiveFilterListBranch.Index;
                    }
                    else if (
                        curLdapToken.Type == LdapTokenType.GroupEnd &&
                        curLdapToken.ScopeApplication == LdapTokenScope.FilterList
                    )
                    {
                        // Add current GroupEnd LdapToken to current LdapBranch.
                        ldapBranchFilterList.Branch.Add(curLdapToken);

						// Append current LdapToken's Content and ContentDecoded values to
						// respective StringBuilders.
						sbLdapBranchContent.Append(curLdapToken.Content);
						sbLdapBranchContentDecoded.Append(curLdapToken.ContentDecoded);

						// Update ldapBranchFilterListDepthMax if LdapTokenEnriched's Depth property
						// value exceeds current ldapBranchFilterListDepthMax value.
						ldapBranchFilterListDepthMax = curLdapToken.Depth > ldapBranchFilterListDepthMax ? curLdapToken.Depth : ldapBranchFilterListDepthMax;

						// No need to update ldapBranchFilterListBooleanOperatorCountMax since
						// BooleanOperator count is only tracked at the branch level in ToBranch
						// (current method) and is only found in GroupStart LdapTokenEnriched which
						// is handled in earlier if block.

                        // Update LdapBranch's Index property with index of current LdapToken.
                        ldapBranchFilterList.Index = i;

                        // If last GroupEnd LdapToken in SearchFilter (since Depth is 0) then append
						// any additional tokens to current LdapBranch before returning.
                        if ((curLdapToken.Depth == 0) && (i < (ldapTokensAndBranchesMerged.Count - 1)))
                        {
                            // Extract all remaining LdapTokens.
                            List<object> remainingLdapTokenArr = ldapTokensAndBranchesMerged.GetRange((i + 1), (ldapTokensAndBranchesMerged.Count - 1 - i));

							// Output error message if anything other than a single Whitespace
							// LdapToken is present at end of recursive branch-building.
							if (
								remainingLdapTokenArr.Count > 1 ||
								(remainingLdapTokenArr.Count == 1 && !(remainingLdapTokenArr[0] is LdapTokenEnriched && ((LdapTokenEnriched)remainingLdapTokenArr[0]).Type == LdapTokenType.Whitespace))
							)
							{
								Console.ForegroundColor = ConsoleColor.Red;
								Console.Error.WriteLine($"ERROR: [Maldaptive.LdapParser]::ToBranch - Invalid LDAP SearchFilter. Non-Whitespace LdapToken(s)/LdapFilter(s) remain at end of recursive branch-building beginning at index {i}: {string.Concat(remainingLdapTokenArr.Select(ldapTokenOrBranch => ldapTokenOrBranch is LdapTokenEnriched ? ((LdapTokenEnriched)ldapTokenOrBranch).Content : ((LdapBranch)ldapTokenOrBranch).Content))}");
								Console.ResetColor();
							}

                            // Add all remaining LdapTokens to current LdapBranch.
                            ldapBranchFilterList.Branch.AddRange(remainingLdapTokenArr);

							// Append remaining LdapTokens' Content and ContentDecoded values to
							// respective StringBuilders.
							sbLdapBranchContent.Append(string.Concat(remainingLdapTokenArr.Select(token => ((LdapTokenEnriched)token).Content)));
							sbLdapBranchContentDecoded.Append(string.Concat(remainingLdapTokenArr.Select(token => ((LdapTokenEnriched)token).ContentDecoded)));

							// No need to update LdapBranch's Length, DepthMax and BooleanOperatorCountMax
							// properties since current if block is for Depth 0 to account only for
							// trailing Whitespace LdapTokens.

                            // Advance LdapBranch's Index property with index of final LdapToken
							// (since all remaining LdapTokens were added to current LdapBranch above).
                            ldapBranchFilterList.Index = ldapTokensAndBranchesMerged.Count - 1;
                        }

						// Update LdapBranch's Content and ContentDecoded properties with respective
						// StringBuilders' results.
						ldapBranchFilterList.Content = sbLdapBranchContent.ToString();
						ldapBranchFilterList.ContentDecoded = sbLdapBranchContentDecoded.ToString();

						// Update LdapBranch's DepthMax and BooleanOperatorCountMax properties with
						// maximum Depth, BooleanOperator count and logical BooleanOperator count values.
						ldapBranchFilterList.DepthMax = ldapBranchFilterListDepthMax;
						ldapBranchFilterList.BooleanOperatorCountMax = ldapBranchFilterListBooleanOperatorCountMax;
						ldapBranchFilterList.BooleanOperatorLogicalCountMax = ldapBranchFilterListBooleanOperatorLogicalCountMax;

						// No need to update LdapBranch's Length, DepthMax and BooleanOperatorCountMax
						// properties since they will be updated by calling recursive method after
						// initial GroupStart LdapToken is prepended.

                        // Return current LdapBranch since current FilterList-scope GroupEnd LdapToken
						// has closed the current LdapBranch.
						return ldapBranchFilterList;
                    }
                    else
                    {
                        // Add current non-GroupStart/non-GroupEnd LdapToken object to current LdapBranch.
                        ldapBranchFilterList.Branch.Add(curLdapToken);

						// Append current LdapToken's Content and ContentDecoded values to respective StringBuilders.
						sbLdapBranchContent.Append(curLdapToken.Content);
						sbLdapBranchContentDecoded.Append(curLdapToken.ContentDecoded);

						// Update ldapBranchFilterListDepthMax if LdapTokenEnriched's Depth property
						// value exceeds current ldapBranchFilterListDepthMax value.
						ldapBranchFilterListDepthMax = curLdapToken.Depth > ldapBranchFilterListDepthMax ? curLdapToken.Depth : ldapBranchFilterListDepthMax;

						// No need to update ldapBranchFilterListBooleanOperatorCountMax since
						// BooleanOperator count is only tracked at the branch level in ToBranch
						// (current method) and is only found in GroupStart LdapTokenEnriched which
						// is handled in earlier if block.
                    }
                }
            }

			// The only LdapBranch reaching this point in the method is the base LdapBranch since
			// this is the original, non-recursive method invocation.

			// Update LdapBranch's Content and ContentDecoded properties with respective StringBuilders' results.
			ldapBranchFilterList.Content = string.Concat(ldapBranchFilterList.Branch.Select(subBranch => subBranch is LdapTokenEnriched ? ((LdapTokenEnriched)subBranch).Content : ((LdapBranch)subBranch).Content));
			ldapBranchFilterList.ContentDecoded = string.Concat(ldapBranchFilterList.Branch.Select(subBranch => subBranch is LdapTokenEnriched ? ((LdapTokenEnriched)subBranch).ContentDecoded : ((LdapBranch)subBranch).ContentDecoded));

			// Update LdapBranch's DepthMax, and BooleanOperatorCountMax and BooleanOperatorLogicalCountMax
			// properties with maximum Depth, BooleanOperator count and logical BooleanOperator count values.
			ldapBranchFilterList.DepthMax = ldapBranchFilterListDepthMax;
			ldapBranchFilterList.BooleanOperatorCountMax = ldapBranchFilterListBooleanOperatorCountMax;
			ldapBranchFilterList.BooleanOperatorLogicalCountMax = ldapBranchFilterListBooleanOperatorLogicalCountMax;

			// Update LdapBranch's Length property with Content property's length.
			ldapBranchFilterList.Length = ldapBranchFilterList.Content.Length;

			// Update LdapBranch's Start property with Start property of first object in Branch property.
			ldapBranchFilterList.Start = ldapBranchFilterList.Branch[0] is LdapTokenEnriched ? ((LdapTokenEnriched)ldapBranchFilterList.Branch[0]).Start : ((LdapBranch)ldapBranchFilterList.Branch[0]).Start;

            // Return current LdapBranch object.
            return ldapBranchFilterList;
        }

        // Overloaded method to handle multiple input formats.
        public static LdapBranch ToBranch(List<LdapTokenEnriched> ldapTokens, LdapBranchType type = LdapBranchType.FilterList, int depth = 0, int index = 0)
        {
            // Return LdapBranch in a nested parse tree/syntax tree structure.
            return LdapParser.ToBranch(
                    LdapParser.ToFilter(ldapTokens)
                );
        }

        // Overloaded method to handle multiple input formats.
        public static LdapBranch ToBranch(List<LdapToken> ldapTokens, LdapBranchType type = LdapBranchType.FilterList, int depth = 0, int index = 0)
        {
            // Return LdapBranch in a nested parse tree/syntax tree structure.
            return LdapParser.ToBranch(
                    LdapParser.ToFilter(
                        LdapParser.ToTokenEnriched(ldapTokens)
                    )
                );
        }

        // Return LdapBranch in a nested parse tree/syntax tree structure.
        public static LdapBranch ToBranch(string ldapSearchFilter, LdapBranchType type = LdapBranchType.FilterList, int depth = 0, int index = 0)
        {
            // Return List of merged LdapFilter and LdapTokenEnriched objects.
            return LdapParser.ToBranch(
                    LdapParser.ToFilter(
                        LdapParser.ToTokenEnriched(
                            LdapParser.Tokenize(ldapSearchFilter)
                        )
                    )
                );
        }

		/// <summary>
		/// This helper method returns list of bit value(s) representing addend(s) for input long value.
		/// </summary>
		public static List<double> ToBitAddend(long inputNum, int bit = 1)
		{
			// Create empty list to hold addend(s) for inputNum.
			List<double> addends = new List<double>();

			// If user input long is negative then convert to positive binary equivalent.
			if (inputNum < 0)
			{
				inputNum = inputNum + (long)System.Math.Pow(2, 32);
			}

			// Convert user input to binary string.
			string binary = System.Convert.ToString(inputNum, 2);

			// If 0 bits are calculated then pad left 32 to accurately calculate all zero character(s).
			if (bit is 0)
			{
				binary = binary.PadLeft(32,'0');
			}

			// Iterate in reverse over each bit in binary string.
			for (int i = 0; i < binary.Length; i++)
			{
				// Extract current bit using negative index to traverse each bit in binary string in reverse.
				char curBit = binary[^(i + 1)];

				// Add current bit's value to addends List if current bit matches bit input parameter.
				if (curBit.ToString() == bit.ToString())
				{
					double curBitValue = System.Math.Pow(2,i);
					addends.Add(curBitValue);
				}
			}

			// Return addends List containing bit value(s) of addend(s) for inputNum input parameter.
			return addends;
		}

		/// <summary>
		/// This helper method returns logical BooleanOperator value for input BooleanOperator character(s).
		/// </summary>
		public static string ToLogicalBooleanOperator(string booleanOperators, bool ignoreTrailingNegation = false)
		{
            // Return null if input booleanOperators string is null or empty.
            if (booleanOperators.Length == 0)
            {
                return null;
            }

			// If optional ignoreTrailingNegation input parameter is defined then remove any trailing
			// negation BooleanOperator ('!') values before calculating logical BooleanOperator value.
			// This parameter is used if user input booleanOperators context chain is extracted from
			// first nested LdapBranch, but logical BooleanOperator value for potential additional
			// LdapBranches (i.e. yet to be added) is desired.
			if (ignoreTrailingNegation)
			{
				booleanOperators = booleanOperators.TrimEnd('!');

				// Return null if input booleanOperators string is now an empty string.
				if (booleanOperators.Length == 0)
				{
					return null;
				}
			}

			// Remove any potential adjacent negation BooleanOperator ('!') values since they logically
			// cancel each other out.
			booleanOperators = booleanOperators.Replace("!!","");

			// Return null if input booleanOperators string is now an empty string.
			if (booleanOperators.Length == 0)
			{
				return null;
			}

			// Default logical BooleanOperator (after above removal of adjacent negation BooleanOperator
			// values) is the trailing character.
			string logicalBooleanOperator = booleanOperators.Substring(booleanOperators.Length - 1);

			// If trailing BooleanOperator character is a non-negation BooleanOperator ('&' or '|')
			// but one or more negation BooleanOperators ('!') are present in BooleanOperator list,
			// calculate if cumulative count of remaining (i.e. non-adjacent) BooleanOperator values
			// is even or odd to determine if compound logical BooleanOperator value (e.g. '!&' or '!|').
			if ((logicalBooleanOperator != "!") && booleanOperators.Contains("!"))
			{
				// Calculate number of remaining (i.e. non-adjacent) negation BooleanOperators.
				int negationBooleanOperatorCount = booleanOperators.Length - booleanOperators.Replace("!","").Length;

				// Calculate logical negation BooleanOperator value based on if cumulative count of
				// remaining (i.e. non-adjacent) BooleanOperator values is even or odd.
				// This works on the basis that an even number of negation BooleanOperator values
				// logically, even if not adjacent, cancel each other out.
				string logicalNegationBooleanOperator = ((negationBooleanOperatorCount % 2) == 0) ? null : "!";

				// Prepend potential logical negation BooleanOperator to logical BooleanOperator value.
				logicalBooleanOperator = logicalNegationBooleanOperator + logicalBooleanOperator;
			}

			// Return final logical BooleanOperator value.
			return logicalBooleanOperator;
		}

        // Overloaded method to handle multiple input formats.
        public static string ToLogicalBooleanOperator(char[] booleanOperators, bool ignoreTrailingNegation = false)
        {
			// Return logical BooleanOperator value for input BooleanOperator character(s).
            return LdapParser.ToLogicalBooleanOperator(new string(booleanOperators), ignoreTrailingNegation);
        }

        // Overloaded method to handle multiple input formats.
        public static string ToLogicalBooleanOperator(List<char> booleanOperators, bool ignoreTrailingNegation = false)
        {
			// Return logical BooleanOperator value for input BooleanOperator character(s).
            return LdapParser.ToLogicalBooleanOperator(new string(booleanOperators.ToArray()), ignoreTrailingNegation);
        }

		/// <summary>
		/// This helper method removes single instance of specified leading character from input string (if present).
		/// </summary>
		public static string TrimStartOne(string inputString, char charToTrim)
		{
			// Remove potential single leading character from input string.
			return inputString.StartsWith(charToTrim) ? inputString.Substring(1) : inputString;
		}

		/// <summary>
		/// This helper method removes single instance of specified trailing character from input string (if present).
		/// </summary>
		public static string TrimEndOne(string inputString, char charToTrim)
		{
			// Remove potential single trailing character from input string.
			return inputString.EndsWith(charToTrim) ? inputString.Substring(0, inputString.Length - 1) : inputString;
		}

		/// <summary>
		/// This helper method removes single instance of specified leading and/or trailing character from input string (if present).
		/// </summary>
		public static string TrimOne(string inputString, char charToTrim)
		{
			// Remove potential single leading and/or trailing character from input string.
			return TrimEndOne(TrimStartOne(inputString, charToTrim), charToTrim);
		}

        /// <summary>
        /// This method orchestrates the invocation of all FindEvil* methods to return complete list
		/// of Detection objects for each Detection "hit" occurring for every input LDAP SearchFilter.
        /// </summary>
        public static List<Detection> FindEvil(List<LdapTokenEnriched> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return empty list of Detections if input ldapTokens is empty.
            if (ldapTokens.Count == 0)
            {
				return new List<Detection>();
            }

            // Create new list of Detections to store combined set of Detections for input ldapTokens.
            List<Detection> detectionHitList = new List<Detection>();

			// If input detectionIDList is null or empty then instantiate it with all valid DetectionID values.
			if (detectionIDList == null)
			{
				detectionIDList = new List<DetectionID>((DetectionID[])Enum.GetValues(typeof(DetectionID)));
			}

			// Convert input LDAP SearchFilter into deeper-parsed formats for most efficient FindEvil*
			// method invocations below.
			List<object> ldapTokensAndFiltersMerged = ToFilter(ldapTokens);
			LdapBranch ldapBranch = ToBranch(ldapTokensAndFiltersMerged);

			// Append any potential Detections from FindEvilInTokenEnriched method for current LDAP SearchFilter.
			detectionHitList.AddRange(
				FindEvilInTokenEnriched(ldapTokens, detectionIDList)
			);

			// Append any potential Detections from FindEvilInFilter method for current LDAP SearchFilter.
			detectionHitList.AddRange(
				FindEvilInFilter(ldapTokensAndFiltersMerged, detectionIDList)
			);

			// Append any potential Detections from FindEvilInBranch method for current LDAP SearchFilter.
			detectionHitList.AddRange(
				FindEvilInBranch(ldapBranch, detectionIDList)
			);

			// Order final list of Detection hits by Start index property.
			detectionHitList = detectionHitList.OrderBy(detection => detection.Start).ToList();

			// Return current list of Detection hits for current LDAP SearchFilter.
			return detectionHitList;
        }

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvil(LdapBranch ldapBranch, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = ldapBranch.Content;

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvil(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
		}

		// Do not overload for List<LdapFilter> format since it intentionally drops non-Filter tokens.

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvil(List<object> ldapTokensAndFiltersMerged, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = string.Join("", ldapTokensAndFiltersMerged.Select(obj => obj is LdapTokenEnriched ? (obj as LdapTokenEnriched).Content : (obj as LdapFilter).Content).ToList());

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvil(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
		}

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvil(List<LdapToken> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvil(
					LdapParser.ToTokenEnriched(ldapTokens)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvil(string ldapSearchFilter, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvil(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
        }

        /// <summary>
        /// This method returns list of Detection objects for each Detection "hit" occurring for
		/// every iteratively traversed token of input LDAP SearchFilter.
        /// </summary>
        public static List<Detection> FindEvilInTokenEnriched(List<LdapTokenEnriched> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return empty list of Detections if input ldapTokens is empty.
            if (ldapTokens.Count == 0)
            {
				return new List<Detection>();
            }

            // Create new list of Detections to store set of Detections for input ldapTokens.
            List<Detection> detectionHitList = new List<Detection>();

			// If input detectionIDList is null or empty then instantiate it with all valid DetectionID values.
			if (detectionIDList == null)
			{
				detectionIDList = new List<DetectionID>((DetectionID[])Enum.GetValues(typeof(DetectionID)));
			}

			// Extract separate list of Whitespace tokens from input ldapTokens for later detections.
			List<LdapTokenEnriched> whitespaceTokens = ldapTokens.Where(token => token.Type == LdapTokenType.Whitespace).ToList();

			// Iterate over and evaluate each defined DetectionID for input LDAP SearchFilter's list of tokens.
			foreach (DetectionID curDetectionID in detectionIDList)
			{
				switch (curDetectionID)
				{
					case DetectionID.CONTEXT_BOOLEANOPERATOR_EXCESSIVE_COUNT:
						// Calculate list of BooleanOperator tokens in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapTokenEnriched> booleanOperatorTokens = ldapTokens.Where(token => token.Type == LdapTokenType.BooleanOperator).ToList();
						double booleanOperatorTokensDepthAvg = booleanOperatorTokens.Count > 0 ? booleanOperatorTokens.Average(token => token.Depth) : 0.0;

						if (
							booleanOperatorTokens.Count >= 10 &&
							booleanOperatorTokensDepthAvg >= 5.0
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of BooleanOperator Tokens in Entire SearchFilter ('{booleanOperatorTokens.Count}') with an Average Depth of '{Math.Round(booleanOperatorTokensDepthAvg, 2)}'",
									"(|(&(co=Albania)(|(&(l=Kukes)(name=Sabi))(name=Ela)(name=Mela)))(&(co=United States of America)(!(!(l=Atlanta)))(!(!name=DBO)))(&(co=Kosovo)(|(name=Abian)(name=Andi)(name=Art)(name=Dredhza)(name=Enisa)(name=Isuf)))(&(co=Another Country)(l=Another City)(|(name=Another Person 1)(name=Another Person 2)(name=Another Person 3))))",
									5.0 * booleanOperatorTokens.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_BOOLEANOPERATOR_NONSHALLOW_EXCESSIVE_COUNT:
						// Calculate list of non-shallow BooleanOperator tokens in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapTokenEnriched> nonShallowBooleanOperatorTokens = ldapTokens.Where(token =>
							token.Type == LdapTokenType.BooleanOperator &&
							token.Depth > 5
						).ToList();
						double nonShallowBooleanOperatorTokensDepthAvg = nonShallowBooleanOperatorTokens.Count > 0 ? nonShallowBooleanOperatorTokens.Average(token => token.Depth) : 0.0;

						if (nonShallowBooleanOperatorTokens.Count >= 10)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Non-Shallow BooleanOperator Tokens in Entire SearchFilter ('{nonShallowBooleanOperatorTokens.Count}') with an Average Depth of '{Math.Round(nonShallowBooleanOperatorTokensDepthAvg, 2)}'",
									"(((((|(&(co=Albania)(|(&(l=Kukes)(name=Sabi))(name=Ela)(name=Mela)))(&(co=United States of America)(!(!(l=Atlanta)))(!(!name=DBO)))(&(co=Kosovo)(|(name=Abian)(name=Andi)(name=Art)(name=Dredhza)(name=Enisa)(name=Isuf)))(&(co=Another Country)(l=Another City)(|(name=Another Person 1)(name=Another Person 2)(name=Another Person 3))))))))",
									5.0 * nonShallowBooleanOperatorTokens.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_EXTENSIBLEMATCHFILTER_EXCESSIVE_COUNT:
						// Calculate list of ExtensibleMatchFilter tokens in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapTokenEnriched> extensibleMatchFilterTokens = ldapTokens.Where(token => token.Type == LdapTokenType.ExtensibleMatchFilter).ToList();
						double extensibleMatchFilterTokensDepthAvg = extensibleMatchFilterTokens.Count > 0 ? extensibleMatchFilterTokens.Average(token => token.Depth) : 0.0;

						if (
							extensibleMatchFilterTokens.Count >= 5 &&
							extensibleMatchFilterTokensDepthAvg >= 5.5
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of ExtensibleMatchFilter Tokens in Entire SearchFilter ('{extensibleMatchFilterTokens.Count}') with an Average Depth of '{Math.Round(extensibleMatchFilterTokensDepthAvg, 2)}'",
									"(&(objectCategory=person)(objectClass=user)(useraccountcontrol=*)(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(!(|(useraccountcontrol:1.2.840.113556.1.4.803:=3)(useraccountcontrol:1.2.840.113556.1.4.803:=6)(useraccountcontrol:1.2.840.113556.1.4.803:=7)(useraccountcontrol:1.2.840.113556.1.4.803:=10)(useraccountcontrol:1.2.840.113556.1.4.803:=11)(useraccountcontrol:1.2.840.113556.1.4.803:=14)(useraccountcontrol:1.2.840.113556.1.4.803:=66)(useraccountcontrol:1.2.840.113556.1.4.803:=514))))",
									5.0 * extensibleMatchFilterTokens.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_WHITESPACE_EXCESSIVE_COUNT:
						// Calculate list of slightly-filtered Whitespace tokens appearing before/after uncommon TokenType in current LDAP SearchFilter
						// and their corresponding average Length and Depth.
						List<LdapTokenEnriched> whitespaceTokensFiltered = whitespaceTokens.Where(token =>
							// Exclude specific noisy scenarios where specific-length Whitespace tokens are automatically added in server-side LDAP logs.
							!(token.TypeBefore == LdapTokenType.BooleanOperator && token.Length == 2) &&
							!(token.TypeAfter == LdapTokenType.BooleanOperator && token.Length == 1) &&
							!(token.TypeBefore == LdapTokenType.GroupEnd && token.TypeAfter == LdapTokenType.GroupStart && token.Length == 2)
						).ToList();
						double whitespaceTokensFilteredLengthAvg = whitespaceTokensFiltered.Count > 0 ? whitespaceTokensFiltered.Average(token => token.Length) : 0.0;
						double whitespaceTokensFilteredDepthAvg = whitespaceTokensFiltered.Count > 0 ? whitespaceTokensFiltered.Average(token => token.Depth) : 0.0;

						if (
							whitespaceTokensFiltered.Count >= 5 &&
							(
								whitespaceTokensFilteredLengthAvg > 1.0 ||
								whitespaceTokensFilteredDepthAvg > 2.75
							)
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Whitespace Tokens in Entire SearchFilter ('{whitespaceTokensFiltered.Count}') with an Average Length of '{Math.Round(whitespaceTokensFilteredLengthAvg, 2)}' and Average Depth of '{Math.Round(whitespaceTokensFilteredDepthAvg, 2)}'",
									" (    &   ( 1.2.840.113556.1.4.8   :1.2.840.113556.1.4.804:=512)  ( |  (     & (     co=    Albania)     (   l=   Kukes) (    name=   Sabi)     ) (    &   (    co= United States of America)  (   l= Atlanta)    (   name=   DBO)     )    )  ) ",
									2.5 * whitespaceTokensFiltered.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_LARGE_WHITESPACE_EXCESSIVE_COUNT:
						// Calculate list of large Whitespace tokens in current LDAP SearchFilter and their corresponding average Length and Depth.
						List<LdapTokenEnriched> whitespaceTokensLarge = whitespaceTokens.Where(token => token.Length >= 3).ToList();
						double whitespaceTokensLargeLengthAvg = whitespaceTokensLarge.Count > 0 ? whitespaceTokensLarge.Average(token => token.Length) : 0.0;
						double whitespaceTokensLargeDepthAvg = whitespaceTokensLarge.Count > 0 ? whitespaceTokensLarge.Average(token => token.Depth) : 0.0;

						if (whitespaceTokensLarge.Count >= 3)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Large Whitespace Tokens in Entire SearchFilter ('{whitespaceTokensLarge.Count}') with an Average Length of '{Math.Round(whitespaceTokensLargeLengthAvg, 2)}' and Average Depth of '{Math.Round(whitespaceTokensLargeDepthAvg, 2)}'",
									" (    &   ( 1.2.840.113556.1.4.8   :1.2.840.113556.1.4.804:=512)  ( |  (     & (     co=    Albania)     (   l=   Kukes) (    name=   Sabi)     ) (    &   (    co= United States of America)  (   l= Atlanta)    (   name=   DBO)     )    )  ) ",
									5.0 * whitespaceTokensLarge.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_WHITESPACE_UNCOMMON_NEIGHBOR_EXCESSIVE_COUNT:
						// Calculate list of Whitespace tokens appearing before/after uncommon TokenType in current LDAP SearchFilter
						// and their corresponding average Length and Depth.
						List<LdapTokenEnriched> whitespaceTokensUncommonNeighbor = whitespaceTokens.Where(token =>
							// Exclude specific noisy scenarios where specific-length Whitespace tokens are automatically added in server-side LDAP logs.
							(token.TypeBefore == LdapTokenType.BooleanOperator && token.Length != 2) ||
							(token.TypeAfter == LdapTokenType.BooleanOperator && token.Length != 1) ||
							token.TypeBefore == LdapTokenType.Attribute ||
							token.TypeBefore == LdapTokenType.ComparisonOperator ||
							token.TypeAfter == LdapTokenType.Attribute ||
							token.TypeAfter == LdapTokenType.ExtensibleMatchFilter ||
							token.TypeAfter == LdapTokenType.Value
						).ToList();
						double whitespaceTokensUncommonNeighborLengthAvg = whitespaceTokensUncommonNeighbor.Count > 0 ? whitespaceTokensUncommonNeighbor.Average(token => token.Length) : 0.0;
						double whitespaceTokensUncommonNeighborDepthAvg = whitespaceTokensUncommonNeighbor.Count > 0 ? whitespaceTokensUncommonNeighbor.Average(token => token.Depth) : 0.0;

						if (
							whitespaceTokensUncommonNeighbor.Count >= 3 &&
							(
								whitespaceTokensUncommonNeighborLengthAvg > 1.0 ||
								whitespaceTokensUncommonNeighborDepthAvg > 2.75
							)
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokens),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Whitespace Tokens With Uncommon Neighboring TokenTypes in Entire SearchFilter ('{whitespaceTokensUncommonNeighbor.Count}') with an Average Length of '{Math.Round(whitespaceTokensUncommonNeighborLengthAvg, 2)}' and Average Depth of '{Math.Round(whitespaceTokensUncommonNeighborDepthAvg, 2)}'",
									" (    &   ( 1.2.840.113556.1.4.8   :1.2.840.113556.1.4.804:=512)  ( |  (     & (     co=    Albania)     (   l=   Kukes) (    name=   Sabi)     ) (    &   (    co= United States of America)  (   l= Atlanta)    (   name=   DBO)     )    )  ) ",
									7.5 * whitespaceTokensUncommonNeighbor.Count
								)
							);
						}

						break;
				}
			}

			// Order final list of Detection hits by Start index property.
			detectionHitList = detectionHitList.OrderBy(detection => detection.Start).ToList();

			// Return current list of Detection hits for current LDAP SearchFilter.
			return detectionHitList;
        }

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvilInTokenEnriched(LdapBranch ldapBranch, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = ldapBranch.Content;

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvilInTokenEnriched(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
		}

		// Do not overload for List<LdapFilter> format since it intentionally drops non-Filter tokens.

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvilInTokenEnriched(List<object> ldapTokensAndFiltersMerged, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = string.Join("", ldapTokensAndFiltersMerged.Select(obj => obj is LdapTokenEnriched ? (obj as LdapTokenEnriched).Content : (obj as LdapFilter).Content).ToList());

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvilInTokenEnriched(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
		}

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInTokenEnriched(List<LdapToken> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInTokenEnriched(
					LdapParser.ToTokenEnriched(ldapTokens)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInTokenEnriched(string ldapSearchFilter, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInTokenEnriched(
					LdapParser.ToTokenEnriched(
						LdapParser.Tokenize(ldapSearchFilter)
					)
                ,detectionIDList);
        }

        /// <summary>
        /// This method returns list of Detection objects for each Detection "hit" occurring for
		/// every iteratively traversed filter of input LDAP SearchFilter.
        /// </summary>
        public static List<Detection> FindEvilInFilter(List<object> ldapTokensAndFiltersMerged, List<DetectionID> detectionIDList = null)
        {
			// Return empty list of Detections if input ldapTokensAndFiltersMerged is empty.
            if (ldapTokensAndFiltersMerged.Count == 0)
            {
				return new List<Detection>();
            }

            // Create new list of Detections to store set of Detections for input ldapTokensAndFiltersMerged.
            List<Detection> detectionHitList = new List<Detection>();

			// If input detectionIDList is null or empty then instantiate it with all valid DetectionID values.
			if (detectionIDList == null)
			{
				detectionIDList = new List<DetectionID>((DetectionID[])Enum.GetValues(typeof(DetectionID)));
			}

			// Extract separate list of LdapFilter objects from input ldapTokensAndFiltersMerged.
			List<LdapFilter> ldapFilters = ldapTokensAndFiltersMerged.Where(obj => obj is LdapFilter).Select(obj => obj as LdapFilter).ToList();

			// Return empty list of Detections if no LdapFilters extracted from input ldapTokensAndFiltersMerged (e.g. if invalid SearchFilter).
            if (ldapFilters.Count == 0)
            {
				return new List<Detection>();
            }

			// Calculate maximum depth from extracted list of LdapFilter objects from input ldapTokensAndFiltersMerged.
			int ldapFiltersMaxDepth = ldapFilters.Max(filter => filter.Depth);

			// Calculate list of Filters containing defined Attributes in current LDAP SearchFilter
			// and their corresponding average Depth and distinct list of Attributes.
			List<LdapFilter> filtersWithDefinedAttributes = ldapFilters.Where(filter => filter.TokenDict[LdapTokenType.Attribute]?.IsDefined == true).ToList();
			double filtersWithDefinedAttributesDepthAvg = filtersWithDefinedAttributes.Count > 0 ? filtersWithDefinedAttributes.Average(token => token.Depth) : 0.0;
			List<string> filtersWithDefinedAttributesDistinctAttributes = filtersWithDefinedAttributes.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
			List<LdapTokenFormat> filtersWithDefinedAttributesDistinctAttributeFormat = filtersWithDefinedAttributes.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

            // Calculate list of Filters containing undefined Attributes in current LDAP SearchFilter
            // and their corresponding average Depth and distinct list of Attributes.
			// Distinct format list not needed since will always be 'Undefined' for undefined Attributes.
            List<LdapFilter> filtersWithUndefinedAttributes = ldapFilters.Where(filter => filter.TokenDict[LdapTokenType.Attribute]?.IsDefined == false).ToList();
            double filtersWithUndefinedAttributesDepthAvg = filtersWithUndefinedAttributes.Count > 0 ? filtersWithUndefinedAttributes.Average(token => token.Depth) : 0.0;
            List<string> filtersWithUndefinedAttributesDistinctAttributes = filtersWithUndefinedAttributes.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();

			// Calculate list of logically excluded Filters containing '>=' or '<=' Range ComparisonOperator in current LDAP SearchFilter
			// and their corresponding average Depth and distinct list of Attributes.
			List<LdapFilter> excludedFiltersWithRangeComparisonOperators = ldapFilters.Where(filter =>
					(filter.ComparisonOperator == ">=" || filter.ComparisonOperator == "<=") &&
					filter.Context.BooleanOperator.LogicalFilterInclusion == false
			).ToList();
			double excludedFiltersWithRangeComparisonOperatorsDepthAvg = excludedFiltersWithRangeComparisonOperators.Count > 0 ? excludedFiltersWithRangeComparisonOperators.Average(token => token.Depth) : 0.0;
			List<string> excludedFiltersWithRangeComparisonOperatorsDistinctAttributes = excludedFiltersWithRangeComparisonOperators.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
			List<LdapTokenFormat> excludedFiltersWithRangeComparisonOperatorsDistinctAttributeFormat = excludedFiltersWithRangeComparisonOperators.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

			// Calculate list of Filters containing defined Bitwise Attribute and '>=' or '<=' Range ComparisonOperator in current LDAP SearchFilter
			// and their corresponding average Depth and distinct list of Attributes.
			List<LdapFilter> definedBitwiseAttributesWithRangeComparisonOperators = ldapFilters.Where(filter =>
					(filter.ComparisonOperator == ">=" || filter.ComparisonOperator == "<=") &&
					filter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.ValueFormat == LdapTokenFormat.Bitwise
			).ToList();
			double definedBitwiseAttributesWithRangeComparisonOperatorsDepthAvg = definedBitwiseAttributesWithRangeComparisonOperators.Count > 0 ? definedBitwiseAttributesWithRangeComparisonOperators.Average(token => token.Depth) : 0.0;
			List<string> definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes = definedBitwiseAttributesWithRangeComparisonOperators.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
			List<LdapTokenFormat> definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributeFormat = definedBitwiseAttributesWithRangeComparisonOperators.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

			// Calculate list of Filters containing defined ByteArray Attribute and '>=' or '<=' Range ComparisonOperator in current LDAP SearchFilter
			// and their corresponding average Depth and distinct list of Attributes.
			List<LdapFilter> definedByteArrayAttributesWithRangeComparisonOperators = ldapFilters.Where(filter =>
					(filter.ComparisonOperator == ">=" || filter.ComparisonOperator == "<=") &&
					filter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.SDSType == LdapAttributeSyntaxSDSType.ByteArray
			).ToList();
			double definedByteArrayAttributesWithRangeComparisonOperatorsDepthAvg = definedByteArrayAttributesWithRangeComparisonOperators.Count > 0 ? definedByteArrayAttributesWithRangeComparisonOperators.Average(token => token.Depth) : 0.0;
			List<string> definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes = definedByteArrayAttributesWithRangeComparisonOperators.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
			List<LdapAttributeSyntaxSDSType> definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributeFormat = definedByteArrayAttributesWithRangeComparisonOperators.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.SDSType).DistinctBy(type => type).ToList();

			// Define list of sensitive Values for later detections identifying these Values despite presence of obfuscation.
			List<string> suspiciousValueArr = new List<string>()
			{
				// Sensitive values for name Attribute.
				"krbtgt",
				"Domain Admins",
				"Domain Controllers",
				// Sensitive values for objectClass Attribute.
				"trustedDomain",
				// Sensitive values for description Attribute.
				"Key Distribution Center Service Account", // "krbtgt"
				"Designated administrators of the domain", // "Domain Admins"
				"All domain controllers in the domain", // "Domain Controllers"
				// Source: https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb
				"password",
				"administrator"
			};
			List<string> suspiciousValueMatchArr;
			string valueDecodedEscapedRegexStr;
			Regex valueRegex;

			// Define list of sensitive Attributes for later detections identifying these Attributes in literal and logical Presence Filter scenarios.
			List<string> suspiciousAttributePresenceFilterArr = new List<string>()
			{
				// Password-related Attributes.
				"msDS-ExecuteScriptPassword",
				"msDS-ManagedPassword",
				"msFVE-RecoveryPassword",
				// Source: https://specterops.io/blog/2024/05/02/manual-ldap-querying-part-2/
				"userPassword",
				"unicodePwd",
				"unixUserPassword",
				"msSFU30Password",
				"orclCommonAttribute",
				"defender-tokenData",
				"ms-Mcs-AdmPwd",
				//
				// SPN/Kerberoasting-related Attributes.
				"servicePrincipalName"
			};
			List<string> suspiciousAttributePresenceFilterMatchArr;

			// Perform subset of Detection evaluation against single list of all Filters in ldapFilters.

			// Iterate over and evaluate each defined DetectionID for input LDAP SearchFilter's list of Filters.
			foreach (DetectionID curDetectionID in detectionIDList)
			{
				switch (curDetectionID)
				{
					case DetectionID.CONTEXT_FILTER_EXCESSIVE_COUNT:
						// Calculate average Depth of all Filters in current LDAP SearchFilter.
						double ldapFiltersDepthAvg = ldapFilters.Count > 0 ? ldapFilters.Average(filter => filter.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						List<string> ldapFiltersDistinctAttributes = ldapFilters.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
						List<LdapTokenFormat> ldapFiltersDistinctAttributeFormat = ldapFilters.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

						if (
							ldapFilters.Count >= 15 &&
							// Remove FPs for large "flat" SearchFilters by requiring some amount of Depth.
							ldapFiltersMaxDepth >= 10
						)
						{
							// Generate new Detection hit and append to list of Detections for input LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Filters in Entire SearchFilter ('{ldapFilters.Count}') with an Average Depth of '{Math.Round(ldapFiltersDepthAvg, 2)}', Composed of '{ldapFiltersDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", ldapFiltersDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{ldapFiltersDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", ldapFiltersDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(|(&(co=Albania)(|(&(l=Kukes)(name=Sabi))(name=Ela)(name=Mela)))(&(co=United States of America)(l=Atlanta)(name=DBO))(&(((((((((co=Kosovo)))))))))(|(name=Abian)(name=Andi)(name=Art)(name=Dredhza)(name=Enisa)(name=Isuf)))(&(co=Another Country)(l=Another City)(|(name=Another Person 1)(name=Another Person 2)(name=Another Person 3))))",
									1.5 * ldapFilters.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_FILTER_NONSHALLOW_EXCESSIVE_COUNT:
						// Calculate list of non-shallow Filters in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapFilter> nonShallowFilters = ldapFilters.Where(filter => filter.Depth >= 5).ToList();
						double nonShallowFiltersDepthAvg = nonShallowFilters.Count > 0 ? nonShallowFilters.Average(filter => filter.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						List<string> nonShallowFiltersDistinctAttributes = nonShallowFilters.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
						List<LdapTokenFormat> nonShallowFiltersDistinctAttributeFormat = nonShallowFilters.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

						if (
							nonShallowFilters.Count >= 15 &&
							nonShallowFiltersDepthAvg > 5.0
						)
						{
							// Generate new Detection hit and append to list of Detections for input LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Non-Shallow Filters in Entire SearchFilter ('{nonShallowFilters.Count}') with an Average Depth of '{Math.Round(nonShallowFiltersDepthAvg, 2)}', Composed of '{nonShallowFiltersDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", nonShallowFiltersDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{nonShallowFiltersDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", nonShallowFiltersDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(((((|(&(co=Albania)(|(&(l=Kukes)(name=Sabi))(name=Ela)(name=Mela)))(&(co=United States of America)(l=Atlanta)(name=DBO))(&(((((((((co=Kosovo)))))))))(|(name=Abian)(name=Andi)(name=Art)(name=Dredhza)(name=Enisa)(name=Isuf)))(&(co=Another Country)(l=Another City)(|(name=Another Person 1)(name=Another Person 2)(name=Another Person 3))))))))",
									1.5 * nonShallowFilters.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_LOGICALLY_EXCLUDED_FILTER_EXCESSIVE_COUNT:
						// Calculate list of logically excluded Filters in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapFilter> excludedFilters = ldapFilters.Where(filter => filter.Context.BooleanOperator.LogicalFilterInclusion == false).ToList();
						double excludedFiltersDepthAvg = excludedFilters.Count > 0 ? excludedFilters.Average(filter => filter.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						List<string> excludedFiltersDistinctAttributes = excludedFilters.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
						List<LdapTokenFormat> excludedFiltersDistinctAttributeFormat = excludedFilters.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

						if (
							excludedFilters.Count >= 5 &&
							excludedFiltersDepthAvg >= 4.75
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Logically Excluded Filters in Entire SearchFilter ('{excludedFilters.Count}') with an Average Depth of '{Math.Round(excludedFiltersDepthAvg, 2)}', Composed of '{excludedFiltersDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", excludedFiltersDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{excludedFiltersDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", excludedFiltersDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(|(&(co=Albania)(!name=Sabi)(!name=Ela)(!(name=Mela)))(&(co=United States of America)(!name=DBO))(&(co=Kosovo)(!(|(name=Abian)(name=Andi)(name=Art)(name=Dredhza)(name=Enisa)(name=Isuf)))(&(co=Another Country)(l=Another City)(|(name=Another Person 1)(name=Another Person 2)(name=Another Person 3)))))",
									5.0 * excludedFilters.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_NOT_EXCESSIVE_COUNT:
						// Calculate list of Filters with Filter-scope NOT BooleanOperators in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapFilter> filtersWithFilterScopeNotBooleanOperators = ldapFilters.Where(filter =>
							filter.BooleanOperator == "!" &&
							filter.TokenDict[LdapTokenType.BooleanOperator]?.ScopeSyntax == LdapTokenScope.Filter
						).ToList();
						double filtersWithFilterScopeNotBooleanOperatorsDepthAvg = filtersWithFilterScopeNotBooleanOperators.Count > 0 ? filtersWithFilterScopeNotBooleanOperators.Average(token => token.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						List<string> filtersWithFilterScopeNotBooleanOperatorsDistinctAttributes = filtersWithFilterScopeNotBooleanOperators.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
						List<LdapTokenFormat> filtersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat = filtersWithFilterScopeNotBooleanOperators.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

						if (
							filtersWithFilterScopeNotBooleanOperators.Count >= 3 &&
							filtersWithFilterScopeNotBooleanOperatorsDepthAvg > 3.0
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Filter-Scope BooleanOperator (NOT) in Entire SearchFilter ('{filtersWithFilterScopeNotBooleanOperators.Count}') with an Average Depth of '{Math.Round(filtersWithFilterScopeNotBooleanOperatorsDepthAvg, 2)}', Composed of '{filtersWithFilterScopeNotBooleanOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", filtersWithFilterScopeNotBooleanOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{filtersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", filtersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(&(co=Albania)(!l=Elbasan)(!l=Durres)(!l=Butrint)(!l=Korca)(!l=Berat))",
									5.0 * filtersWithFilterScopeNotBooleanOperators.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_NOT_NONSHALLOW_EXCESSIVE_COUNT:
						// Calculate list of non-shallow Filters with Filter-scope NOT BooleanOperators in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapFilter> nonShallowFiltersWithFilterScopeNotBooleanOperators = ldapFilters.Where(filter =>
							filter.BooleanOperator == "!" &&
							filter.TokenDict[LdapTokenType.BooleanOperator]?.ScopeSyntax == LdapTokenScope.Filter &&
							filter.Depth >= 5
						).ToList();
						double nonShallowFiltersWithFilterScopeNotBooleanOperatorsDepthAvg = nonShallowFiltersWithFilterScopeNotBooleanOperators.Count > 0 ? nonShallowFiltersWithFilterScopeNotBooleanOperators.Average(token => token.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						List<string> nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributes = nonShallowFiltersWithFilterScopeNotBooleanOperators.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();
						List<LdapTokenFormat> nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat = nonShallowFiltersWithFilterScopeNotBooleanOperators.Select(filter => filter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat).DistinctBy(format => format).ToList();

						if (nonShallowFiltersWithFilterScopeNotBooleanOperators.Count >= 3)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Non-Shallow Filter-Scope BooleanOperator (NOT) in Entire SearchFilter ('{nonShallowFiltersWithFilterScopeNotBooleanOperators.Count}') with an Average Depth of '{Math.Round(nonShallowFiltersWithFilterScopeNotBooleanOperatorsDepthAvg, 2)}', Composed of '{nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", nonShallowFiltersWithFilterScopeNotBooleanOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(((((&(co=Albania)(!l=Elbasan)(!l=Durres)((((!l=Butrint))))(!l=Korca)(!l=Berat))))))",
									5.0 * nonShallowFiltersWithFilterScopeNotBooleanOperators.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_UNDEFINED_ATTRIBUTE_EXCESSIVE_DISTINCT_COUNT:
						if (
							filtersWithUndefinedAttributesDistinctAttributes.Count >= 5 &&
							filtersWithUndefinedAttributesDepthAvg > 4.5
						)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Distinct Count ('{filtersWithUndefinedAttributesDistinctAttributes.Count}') of Undefined Attributes with an Average Depth of '{Math.Round(filtersWithUndefinedAttributesDepthAvg, 2)}', Composed of '{filtersWithUndefinedAttributesDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", filtersWithUndefinedAttributesDistinctAttributes.Select(filter => $"'{filter}'"))}) - Distinct Count ('{filtersWithDefinedAttributesDistinctAttributes.Count}') of Defined Attribute(s): {string.Join(", ", filtersWithDefinedAttributesDistinctAttributes.Select(attribute => $"'{attribute}'"))}",
									"(|(notDefined1=Kukes)(notDefined2=Tirana)(notDefined3=Prishtina)(notDefined4=Gjakova)(notDefinedRepeat=Gjilan)(notDefinedRepeat=Vushtrri)(notDefinedRepeat=Prizren))",
									15.0 * filtersWithUndefinedAttributesDistinctAttributes.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_UNDEFINED_ATTRIBUTE_NONSHALLOW_EXCESSIVE_DISTINCT_COUNT:
						// Calculate list of non-shallow Filters containing undefined Attributes in current LDAP SearchFilter and their corresponding average Depth.
						List<LdapFilter> nonShallowFiltersWithUndefinedAttributes = filtersWithUndefinedAttributes.Where(filter => filter.Depth >= 5).ToList();
						double nonShallowFiltersWithUndefinedAttributesDepthAvg = nonShallowFiltersWithUndefinedAttributes.Count > 0 ? nonShallowFiltersWithUndefinedAttributes.Average(token => token.Depth) : 0.0;

						// Calculate distinct list of Attributes from above list of Filters.
						// Distinct format list not needed since will always be 'Undefined' for undefined Attributes.
						List<string> nonShallowFiltersWithUndefinedAttributesDistinctAttributes = nonShallowFiltersWithUndefinedAttributes.Select(filter => filter.Attribute).DistinctBy(attribute => attribute).ToList();

						if (nonShallowFiltersWithUndefinedAttributesDistinctAttributes.Count >= 5)
						{
							// Generate new Detection hit and append to list of Detections for input LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Distinct Count ('{nonShallowFiltersWithUndefinedAttributesDistinctAttributes.Count}') of Non-Shallow Undefined Attributes with an Average Depth of '{Math.Round(nonShallowFiltersWithUndefinedAttributesDepthAvg, 2)}', Composed of '{nonShallowFiltersWithUndefinedAttributesDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", nonShallowFiltersWithUndefinedAttributesDistinctAttributes.Select(filter => $"'{filter}'"))}) - Distinct Count ('{filtersWithDefinedAttributesDistinctAttributes.Count}') of Defined Attribute(s): {string.Join(", ", filtersWithDefinedAttributesDistinctAttributes.Select(attribute => $"'{attribute}'"))}",
									"((((((|(notDefined1=Kukes)(notDefined2=Tirana)(notDefined3=Prishtina)(notDefined4=Gjakova)(notDefinedRepeat=Gjilan)(notDefinedRepeat=Vushtrri)(notDefinedRepeat=Prizren)))))))",
									15.0 * nonShallowFiltersWithUndefinedAttributesDistinctAttributes.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_EXCLUDED_FILTER_EXCESSIVE_COUNT:
						if (excludedFiltersWithRangeComparisonOperators.Count >= 2)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Count of Logically Excluded Filters Containing '>=' or '<=' Range ComparisonOperator in Entire SearchFilter ('{excludedFiltersWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(excludedFiltersWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{excludedFiltersWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", excludedFiltersWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(&(sAMAccountType=*)(!(sAMAccountType<=805306367))(!(sAMAccountType>=805306369)))",
									5.0 * excludedFiltersWithRangeComparisonOperators.Count
								)
							);
						}

						break;
					case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_EXCLUDED_FILTER_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT:
						if (excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Count >= 2)
						{
							// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
							detectionHitList.Add(
								new Detection(
									ToBranch(ldapTokensAndFiltersMerged),
									"Official_MaLDAPtive_Ruleset",
									new DateTime(2024, 07, 04),
									curDetectionID,
									$"Excessive Distinct Count ('{excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Count}') of Attributes in Logically Excluded Filters Containing '>=' or '<=' Range ComparisonOperator in Entire SearchFilter (Total Count='{excludedFiltersWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(excludedFiltersWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{excludedFiltersWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", excludedFiltersWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
									"(&(sAMAccountType=*)(!(sAMAccountType<=805306367))(!(userAccountControl>=805306369)))",
									5.0 * excludedFiltersWithRangeComparisonOperatorsDistinctAttributes.Count
								)
							);
						}

						break;
                    case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE_EXCESSIVE_COUNT:
                        if (definedBitwiseAttributesWithRangeComparisonOperators.Count >= 2)
                        {
                            // Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
                            detectionHitList.Add(
                                new Detection(
                                    ToBranch(ldapTokensAndFiltersMerged),
                                    "Official_MaLDAPtive_Ruleset",
                                    new DateTime(2024, 07, 04),
                                    curDetectionID,
                                    $"Excessive Count of Filters Containing Defined Bitwise Attributes and '>=' or '<=' Range ComparisonOperator in Entire SearchFilter ('{definedBitwiseAttributesWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(definedBitwiseAttributesWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
                                    "(&(sAMAccountType=*)(sAMAccountType>=805306367)(sAMAccountType<=805306369))",
                                    5.0 * definedBitwiseAttributesWithRangeComparisonOperators.Count
                                )
                            );
                        }

                        break;
                    case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT:
                        if (definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Count >= 2)
                        {
                            // Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
                            detectionHitList.Add(
                                new Detection(
                                    ToBranch(ldapTokensAndFiltersMerged),
                                    "Official_MaLDAPtive_Ruleset",
                                    new DateTime(2024, 07, 04),
                                    curDetectionID,
                                    $"Excessive Distinct Count ('{definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}') of Attributes in Filters Containing Defined Bitwise Attributes and '>=' or '<=' Range ComparisonOperator in Entire SearchFilter (Total Count='{definedBitwiseAttributesWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(definedBitwiseAttributesWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
                                    "(&(sAMAccountType=*)(sAMAccountType>=805306367)(userAccountControl<=805306369))",
                                    5.0 * definedBitwiseAttributesWithRangeComparisonOperatorsDistinctAttributes.Count
                                )
                            );
                        }

                        break;
                    case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE_EXCESSIVE_COUNT:
                        if (definedByteArrayAttributesWithRangeComparisonOperators.Count >= 2)
                        {
                            // Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
                            detectionHitList.Add(
                                new Detection(
                                    ToBranch(ldapTokensAndFiltersMerged),
                                    "Official_MaLDAPtive_Ruleset",
                                    new DateTime(2024, 07, 04),
                                    curDetectionID,
                                    $"Excessive Count of Filters Containing Defined ByteArray Attributes and '>=' or '<=' Range ComparisonOperator in Entire SearchFilter ('{definedByteArrayAttributesWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(definedByteArrayAttributesWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
                                    "(&(userPassword>==)(userPassword<=~))",
                                    5.0 * definedByteArrayAttributesWithRangeComparisonOperators.Count
                                )
                            );
                        }

                        break;
                    case DetectionID.CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT:
                        if (definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Count >= 2)
                        {
                            // Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
                            detectionHitList.Add(
                                new Detection(
                                    ToBranch(ldapTokensAndFiltersMerged),
                                    "Official_MaLDAPtive_Ruleset",
                                    new DateTime(2024, 07, 04),
                                    curDetectionID,
                                    $"Excessive Distinct Count ('{definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}') of Attributes in Filters Containing Defined ByteArray Attributes and '>=' or '<=' Range ComparisonOperator in Entire SearchFilter (Total Count='{definedByteArrayAttributesWithRangeComparisonOperators.Count}') with an Average Depth of '{Math.Round(definedByteArrayAttributesWithRangeComparisonOperatorsDepthAvg, 2)}', Composed of '{definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Count}' Distinct Attribute(s) ({string.Join(", ", definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Select(filter => $"'{filter}'"))}) with '{definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Count}' Distinct Format(s) ({string.Join(", ", definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributeFormat.Select(filter => $"'{filter}'"))})",
                                    "(&(userPassword>==)(objectSid<=~))",
                                    5.0 * definedByteArrayAttributesWithRangeComparisonOperatorsDistinctAttributes.Count
                                )
                            );
                        }

                        break;
				}
			}

			// Perform remaining Detection evaluation iteratively against each individual Filter in ldapFilters.
			foreach (LdapFilter ldapFilter in ldapFilters)
			{
				// Calculate count of Protected wildcard characters ('*') and non-wildcard characters in Value.
				int wildcardCharCount = ldapFilter.TokenDict[LdapTokenType.Value].Context.Value.ContentParsedList.Where(charObj => charObj.Format == LdapValueParsedFormat.Protected && charObj.Content == "*").ToList().Count;
				int nonWildcardCharCount = ldapFilter.TokenDict[LdapTokenType.Value].Context.Value.ContentParsedList.Count - wildcardCharCount;

				// Calculate number of potential leading zeroes for positive or negative non-zero integer Value.
				int leadingZeroCount = 0;
				if (
					(
						ldapFilter.ValueDecoded.StartsWith("0") ||
						ldapFilter.ValueDecoded.StartsWith("-0")
					) &&
					Regex.Match(ldapFilter.ValueDecoded, @"^-?0+[1-9]\d*$").Success
				)
				{
					leadingZeroCount = ldapFilter.ValueDecoded.TrimStart('-').Length - ldapFilter.ValueDecoded.TrimStart('-').TrimStart('0').Length;
				}

				// Iterate over and evaluate each defined DetectionID for current Filter LdapBranch.
				foreach (DetectionID curDetectionID in detectionIDList)
				{
					switch (curDetectionID)
					{
						case DetectionID.CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_AND:
							if (
								ldapFilter.BooleanOperator == "&" &&
								ldapFilter.TokenDict[LdapTokenType.BooleanOperator]?.ScopeSyntax == LdapTokenScope.Filter
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter-Scope BooleanOperator (AND) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(&co=Albania)",
										7.5
									)
								);
							}

							break;
						case DetectionID.CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_OR:
							if (
								ldapFilter.BooleanOperator == "|" &&
								ldapFilter.TokenDict[LdapTokenType.BooleanOperator]?.ScopeSyntax == LdapTokenScope.Filter
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter-Scope BooleanOperator (OR) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(|co=Albania)",
										7.5
									)
								);
							}

							break;
						case DetectionID.FILTER_BRANCH_WITH_GAPPED_BOOLEANOPERATOR:
							if ((ldapFilter.Context.BooleanOperator.FilterListBooleanOperatorDistance - ldapFilter.Context.BooleanOperator.FilterBooleanOperatorTokenListCount) >= 2)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter LdapBranch With Gapped BooleanOperator Context Chain (gap distance='{ldapFilter.Context.BooleanOperator.FilterListBooleanOperatorDistance}') (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(&((co=Albania)))",
										10.0 * ldapFilter.Context.BooleanOperator.FilterListBooleanOperatorDistance
									)
								);
							}

							break;
						case DetectionID.LOGICALLY_INCLUDED_FILTER_BRANCH_NOT_AND:
							if (
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == true &&
								ldapFilter.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!&" &&
								// Exclude specific noisy scenarios.
								!(
									ldapFilter.Attribute == "msExchRoleAssignmentFlags" &&
									ldapFilter.Depth <= 8
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Logically Included Filter LdapBranch Via '!&' (NOT-AND) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(!(&(!co=Albania)(!l=Kukes)))",
										22.5
									)
								);
							}

							break;
						case DetectionID.LOGICALLY_INCLUDED_FILTER_BRANCH_NOT_OR:
							if (
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == true &&
								ldapFilter.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!|"
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Logically Included Filter LdapBranch Via '!|' (NOT-OR) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(!(|(!co=Albania)(!l=Kukes)))",
										22.5
									)
								);
							}

							break;
						case DetectionID.LOGICALLY_EXCLUDED_FILTER_BRANCH_NOT_AND:
							if (
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == false &&
								ldapFilter.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!&" &&
								// Exclude specific noisy scenarios.
								!(
									ldapFilter.Attribute == "msExchRoleAssignmentFlags" &&
									ldapFilter.Depth <= 8
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Logically Excluded Filter LdapBranch Via '!&' (NOT-AND) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(!(&(co=Albania)(l=Kukes)))",
										22.5
									)
								);
							}

							break;
						case DetectionID.LOGICALLY_EXCLUDED_FILTER_BRANCH_NOT_OR:
							if (
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == false &&
								ldapFilter.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!|" &&
								// Exclude specific noisy scenarios.
								!(
									ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "objectCategory" &&
									ldapFilter.Depth <= 8
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Logically Excluded Filter LdapBranch Via '!|' (NOT-OR) (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(!(|(co=Albania)(l=Kukes)))",
										22.5
									)
								);
							}

							break;
						case DetectionID.CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_EXCESSIVE_COUNT:
							if (
								ldapFilter.Context.BooleanOperator.HistoricalBooleanOperatorCount >= 5 &&
								// Remove FPs for large "flat" SearchFilters by requiring some amount of Depth.
								ldapFilter.Depth >= 10
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Excessive Count of FilterList-Scope BooleanOperators ('{ldapFilter.Context.BooleanOperator.HistoricalBooleanOperatorCount}') (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(|(&(|(&(|(!(&(|(co=Albania)(|l=Kukes)))))))))",
										10.0 * ldapFilter.Depth
									)
								);
							}

							break;
						case DetectionID.CONTEXT_FILTER_EXCESSIVE_DEPTH:
							if (ldapFilter.Depth >= 10)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Excessive Depth of Filter LdapBranch ('{ldapFilter.Depth}') (Attribute='{ldapFilter.Attribute}')",
										"(((((co=Albania)))))",
										2.5 * ldapFilter.Depth
									)
								);
							}

							break;
						case DetectionID.UNDEFINED_EXTENSIBLEMATCHFILTER:
							if (ldapFilter.TokenDict[LdapTokenType.ExtensibleMatchFilter]?.IsDefined == false)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Undefined ExtensibleMatchFilter: '{ldapFilter.ExtensibleMatchFilter}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(sAMAccountType:notDefined:=Kukes)",
										25.0
									)
								);
							}

							break;
						case DetectionID.UNDEFINED_ATTRIBUTE_INVALID_SPECIAL_CHARS:
							// Break if Attribute is defined.
							if (ldapFilter.TokenDict[LdapTokenType.Attribute]?.IsDefined == true)
							{
								break;
							}

							// Extract any invalid special characters found in Attribute of current Filter.
							string invalidSpecialCharStr = Regex.Replace(ldapFilter.Attribute, "[A-Za-z0-9-.]", "");

							if (invalidSpecialCharStr.Length > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Undefined Attribute Containing Unsupported Special Characters ('{invalidSpecialCharStr}'): '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(|(+_()_+=Obfuscation)(1+2=3))",
										75.0
									)
								);
							}

							break;
						case DetectionID.DEFINED_ATTRIBUTE_ABNORMAL_SYNTAX:
							if (
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.IsDefined == true &&
								!string.Equals(ldapFilter.Attribute,ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name, StringComparison.OrdinalIgnoreCase) &&
								!string.Equals(ldapFilter.Attribute,ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.OID) &&
								!string.Equals(ldapFilter.Attribute,$"OID.{ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.OID}", StringComparison.OrdinalIgnoreCase)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Defined Attribute with Abnormal Syntax: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(001.00002.840.00113556.1.000004.1=Kukes)",
										20.0
									)
								);
							}

							break;
						case DetectionID.DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_OID_PREFIX:
							if (
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Format == LdapTokenFormat.OID &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.IsDefined == true &&
								ldapFilter.Attribute.StartsWith("OID.", StringComparison.OrdinalIgnoreCase)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Defined Attribute with OID Syntax Containing OID Prefix: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(OID.1.2.840.113556.1.4.1=Kukes)",
										5.0
									)
								);
							}

							break;
						case DetectionID.DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_ZEROS:
							if (
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Format == LdapTokenFormat.OID &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.IsDefined == true &&
								!string.Equals(ldapFilter.Attribute,ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.OID) &&
								!string.Equals(ldapFilter.Attribute,$"OID.{ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.OID}", StringComparison.OrdinalIgnoreCase) &&
								Regex.Match($".{ldapFilter.Attribute}", @"\.0+[1-9]|\.0{2,}").Success
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Defined Attribute with OID Syntax Containing Unnecessary Zeros: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(001.00002.840.00113556.1.000004.1=Kukes)",
										25.0
									)
								);
							}

							break;
						case DetectionID.COMPARISONOPERATOR_RANGE_EXCLUDED:
							if (
								(ldapFilter.ComparisonOperator == ">=" || ldapFilter.ComparisonOperator == "<=") &&
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == false &&
								// Exclude specific noisy scenarios.
								!(
									ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.ValueFormat == LdapTokenFormat.IntEnumeration &&
									ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "msDS-Behavior-Version" &&
									ldapFilter.Depth <= 5
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains '>=' or '<=' Range ComparisonOperator for Logically Excluded Filter (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(&(sAMAccountType=*)(!(sAMAccountType<=805306367))(!(sAMAccountType>=805306369)))",
										10.0
									)
								);
							}

							break;
						case DetectionID.COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE:
							if (
								(ldapFilter.ComparisonOperator == ">=" || ldapFilter.ComparisonOperator == "<=") &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.ValueFormat == LdapTokenFormat.Bitwise &&
								// Exclude specific noisy scenarios.
								!(
									(
										ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "sAMAccountType" ||
										ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "mSMQNT4Flags"
									) &&
									ldapFilter.Depth <= 2
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains '>=' or '<=' Range ComparisonOperator for Defined Bitwise Attribute: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(&(sAMAccountType>=805306367)(sAMAccountType<=805306369)(!(sAMAccountType=805306367))(!(sAMAccountType=805306369)))",
										35.0
									)
								);
							}

							break;
						case DetectionID.COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE:
							if (
								(ldapFilter.ComparisonOperator == ">=" || ldapFilter.ComparisonOperator == "<=") &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.SDSType == LdapAttributeSyntaxSDSType.ByteArray &&
								// Exclude specific noisy scenarios.
								!(
									ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "objectSid" &&
									ldapFilter.Depth <= 5
								)
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains '>=' or '<=' Range ComparisonOperator for Defined ByteArray Attribute: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(&(userPassword>==)(userPassword<=~))",
										35.0
									)
								);
							}

							break;
						case DetectionID.SPECIFIC_ATTRIBUTE_ANR_OID_SYNTAX:
							if (
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "aNR" &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Format == LdapTokenFormat.OID
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains aNR (Ambiguous Name Resolution) Attribute with OID Syntax: '{ldapFilter.Attribute}' (Depth='{ldapFilter.Depth}')",
										"(1.2.840.113556.1.4.1208=krbtgt)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_ATTRIBUTE_WITH_OID_SYNTAX:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.Attribute &&
									token.Format == LdapTokenFormat.OID
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN Attribute with OID Syntax: '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										"(distinguishedName=2.5.4.3=dbo,CN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_ATTRIBUTE_WITH_HEX_ENCODING:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.Attribute &&
									ParseLdapValue(token.Content)?.Where(subToken => subToken.Format == LdapValueParsedFormat.Hex).ToList().Count > 0
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN Attribute with Hex-Encoded Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=\63N=dbo,CN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_COMPARISONOPERATOR_WITH_HEX_ENCODING:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.ComparisonOperator &&
									(
										token.Content == @"\3D" ||
										token.Content == @"\3d"
									)
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN ComparisonOperator with Hex-Encoded Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=CN\3Ddbo,CN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_COMMADELIMITER_WITH_HEX_ENCODING:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.CommaDelimiter &&
									(
										token.Content == @"\2C" ||
										token.Content == @"\2c"
									)
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN CommaDelimiter with Hex-Encoded Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=CN=dbo\2CCN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_WHITESPACE_WITH_HEX_ENCODING:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.Whitespace &&
									token.Content.Contains(@"\20")
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN Whitespace with Hex-Encoded Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=CN=dbo\20,CN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_VALUE_ENCAPSULATED_WITH_DOUBLE_QUOTES:
							if (
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Count > 0 &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.TokenList.Where(token =>
									token.SubType == LdapTokenSubType.RDN &&
									token.Type == LdapTokenType.Value &&
									token.Content.StartsWith('"') &&
									token.Content.EndsWith('"')
								).ToList().Count > 0
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains RDN Value Encapsulated with Double Quotes: '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=CN=""dbo"",CN=Users,DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.RDN_EXCESSIVE_WHITESPACE:
							// Calculate count of Whitespace RDN sub-tokens in Value.
							int whitespaceRdnCount = ldapFilter.TokenDict[LdapTokenType.Value].TokenList.Where(token =>
								token.SubType == LdapTokenSubType.RDN &&
								token.Type == LdapTokenType.Whitespace
							).ToList().Count;

							if (whitespaceRdnCount >= 2)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter DN Value Contains Excessive Count ('{whitespaceRdnCount}') of RDN Whitespace Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										@"(distinguishedName=   CN = dbo , CN=Users , DC=contoso,DC=local)",
										25.0
									)
								);
							}

							break;
						case DetectionID.INT_VALUE_WITH_PREPENDED_ZERO:
							if (
								leadingZeroCount == 1 &&
								ldapFilter.Depth >= 3
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains Non-Zero Integer With Single Unnecessary Leading Zero: '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										"(adminCount=01)",
										25.0
									)
								);
							}

							break;
						case DetectionID.INT_VALUE_WITH_PREPENDED_ZEROES:
							if (leadingZeroCount > 1)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains Non-Zero Integer With Multiple Unnecessary Leading Zero(s) ('{leadingZeroCount}'): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Format='{ldapFilter.TokenDict[LdapTokenType.Attribute].Context.Attribute.ValueFormat}', Depth='{ldapFilter.Depth}')",
										"(adminCount=01)",
										25.0
									)
								);
							}

							break;
						case DetectionID.DATETIME_VALUE_WITH_OBFUSCATED_MILLISECONDS:
							// Break if Value format is not DateTime.
							if (ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.ValueFormat != LdapTokenFormat.DateTime)
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of obfuscation via hex-encoded character(s).
							if (
								Regex.Match(ldapFilter.ValueDecoded, @"^\d{14}\..*Z").Success &&
								!Regex.Match(ldapFilter.ValueDecoded, @"^\d{14}\.\d{0,10}Z$").Success
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains DateTime Value With Non-Standard Millisecond Obfuscation Syntax: '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(whenCreated=20080217112855.1337KaZanPlehrash)",
										15.0
									)
								);
							}

							break;
						case DetectionID.VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS:
							// Break if Value (excluding ByteArray format) does not contain any escape characters ('\') required for hex encoding syntax.
							if (
								!ldapFilter.Value.Contains('\\') ||
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.SDSType == LdapAttributeSyntaxSDSType.ByteArray
							)
							{
								break;
							}

							// Calculate list and count of parsed hex encoded alphanumeric characters in Value.
							List<LdapValueParsed> parsedHexChars = ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.ContentParsedList.Where(obj =>
								obj.Format == LdapValueParsedFormat.Hex &&
								(
									obj.Class == CharClass.Alpha ||
									obj.Class == CharClass.Num
								)
							).ToList();
							int parsedAlphanumericHexCharCount = parsedHexChars.Count;

							// Break if Value does not contain any hex encoded alphanumeric characters.
							if (parsedAlphanumericHexCharCount == 0)
							{
								break;
							}

							// Calculate counts of hex encoded alphanumeric and non-alphanumeric characters to help identify byte array
							// scenarios where the Attribute is unknown (thus skipping the first SDSType check in this Detection logic).
							int parsedCharCount = ldapFilter.TokenDict[LdapTokenType.Value].Context.Value.ContentParsedList.Count;
							int parsedNonAlphanumericHexCharCount = ldapFilter.TokenDict[LdapTokenType.Value].Context.Value.ContentParsedList.Where(obj =>
								obj.Format == LdapValueParsedFormat.Hex &&
								! (
									obj.Class == CharClass.Alpha ||
									obj.Class == CharClass.Num
								)
							).ToList().Count;
							bool isByteArrayValue = (
								parsedCharCount >= 15 &&
								parsedNonAlphanumericHexCharCount >= 5
							) ? true : false;

							if (
								parsedAlphanumericHexCharCount > 0 &&
								isByteArrayValue == false
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains Excessive Count ('{parsedAlphanumericHexCharCount}') of Hex-Encoded Alphanumeric Character(s) ({string.Join(", ", parsedHexChars.Select(obj => $"'{obj.Content}'=>'{obj.ContentDecoded}'").ToList())}): '{ldapFilter.Value}' => '{ldapFilter.ValueDecoded}'",
										@"(name=\6br\42t\67t)",
										25.0 * parsedAlphanumericHexCharCount
									)
								);
							}

							break;
						case DetectionID.VALUE_WITH_EXCESSIVE_WILDCARD_COUNT:
							if (wildcardCharCount >= 3)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains Excessive Count ('{wildcardCharCount}') of Wildcard Character(s): '{ldapFilter.Value}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(name=*rb*g*)",
										20.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_MATCHED_WITH_WILDCARD:
							// Break if Value does not contain 1 wildcard character ('*') and 2+ non-wildcard characters to avoid FPs like (name=*a*).
							if (
								wildcardCharCount == 0 ||
								nonWildcardCharCount < 2
							)
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of obfuscation via wildcard character(s).
							valueDecodedEscapedRegexStr = string.Join("", ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.ContentParsedList.Select(charObj => (charObj.Format == LdapValueParsedFormat.Protected && charObj.Content == "*") ? ".*" : Regex.Escape(charObj.ContentDecoded)).ToArray());
							valueRegex = new Regex("^" + valueDecodedEscapedRegexStr + "$", RegexOptions.IgnoreCase);
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => valueRegex.IsMatch(val)).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
									    $"Filter Value Contains Wildcard Character(s) and Resolves to Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(name=krb*gt)",
										20.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_WITH_HEX_ENCODING:
							// Break if Value does not contain any hex-encoded characters.
							if (ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.ContentParsedList.Where(val => (val.IsDecoded && val.Format == LdapValueParsedFormat.Hex)).ToList().Count == 0)
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of obfuscation via hex-encoded character(s).
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => (string.Equals(ldapFilter.TokenDict[LdapTokenType.Value]?.ContentDecoded, val, StringComparison.OrdinalIgnoreCase))).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Contains Hex-Encoded Character(s) and Resolves to Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										@"(name=kr\62tgt)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_WITHOUT_OBFUSCATION_APPROXIMATELY_EQUAL_COMPARISONOPERATOR:
							// Break if Filter does not have the approximately equal ComparisonOperator ('~=').
							if (ldapFilter.ComparisonOperator != "~=")
							{
								break;
							}

							// Detect any previously-defined sensitive Value without the presence of obfuscation.
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => (string.Equals(ldapFilter.Value, val, StringComparison.OrdinalIgnoreCase))).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Does Not Contain Obfuscation But Has Approximately Equal ComparisonOperator (~=) and Is Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(name~=krbtgt)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_WITHOUT_OBFUSCATION:
							// Detect any previously-defined sensitive Value without the presence of obfuscation.
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => (string.Equals(ldapFilter.Value, val, StringComparison.OrdinalIgnoreCase))).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Value Does Not Contain Obfuscation and Is Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(name=krbtgt)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_WITHOUT_OBFUSCATION_WITH_SPECIFIC_ATTRIBUTE_ANR:
							// Break if Attribute name is not aNR.
							if (ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name != "aNR")
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of an aNR Attribute without the presence of obfuscation.
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => (
								string.Equals(ldapFilter.Value, val, StringComparison.OrdinalIgnoreCase) ||
								string.Equals(ldapFilter.Value, $"={val}", StringComparison.OrdinalIgnoreCase)
							)).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains aNR (Ambiguous Name Resolution) Attribute and Value Does Not Contain Obfuscation and Is Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(aNR=krbtgt)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_SUBSTRING_WITH_LOGICAL_WILDCARD_WITH_SPECIFIC_ATTRIBUTE_ANR:
							// Break if Attribute name is not aNR.
							if (ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name != "aNR")
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of aNR's logical trailing wildcard character ('*').
							valueDecodedEscapedRegexStr = string.Join("", ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.ContentParsedList.Select(charObj => (charObj.Format == LdapValueParsedFormat.Protected && charObj.Content == "*") ? ".*" : Regex.Escape(charObj.ContentDecoded)).ToArray());
							valueRegex = new Regex("^" + valueDecodedEscapedRegexStr + ".*", RegexOptions.IgnoreCase);
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => valueRegex.IsMatch(val)).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains aNR (Ambiguous Name Resolution) Attribute and Value Substring (With Logical Trailing Wildcard) Matches Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(aNR=krb)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_VALUE_SUBSTRING_WITH_WILDCARD_WITH_SPECIFIC_ATTRIBUTE_ANR:
							// Break if Attribute name is not an aNR with 1+ wildcard characters ('*').
							if (
								!(
									ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name == "aNR" &&
									wildcardCharCount >= 1
								)
							)
							{
								break;
							}

							// Detect any previously-defined sensitive Value in the presence of aNR's logical trailing wildcard character ('*')
							// with the additional undocumented caveat of everything after the first explicit wildcard being discarded.
							valueDecodedEscapedRegexStr = string.Join("", ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.ContentParsedList.Select(charObj => (charObj.Format == LdapValueParsedFormat.Protected && charObj.Content == "*") ? ".*" : Regex.Escape(charObj.ContentDecoded)).ToArray());
							string valueSubstringDecodedEscapedRegexStr = valueDecodedEscapedRegexStr = valueDecodedEscapedRegexStr.Substring(0, valueDecodedEscapedRegexStr.IndexOf(".*"));
							valueRegex = new Regex("^" + valueSubstringDecodedEscapedRegexStr + ".*", RegexOptions.IgnoreCase);
							suspiciousValueMatchArr = suspiciousValueArr.Where(val => valueRegex.IsMatch(val)).ToList();
							if (suspiciousValueMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains aNR (Ambiguous Name Resolution) Attribute and Value Substring (With Logical Trailing Wildcard) Up To the First Explicit Wildcard Character ('*') Matches Specific Suspicious Value: '{suspiciousValueMatchArr[0]}' (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
										"(aNR=krb*TrailingSubstringDoesNotExist)",
										15.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_ATTRIBUTE_PRESENCE_FILTER:
							// Break if Value is not explicit Presence Filter syntax.
							if (ldapFilter.Value != "*")
							{
								break;
							}

							// Detect any previously-defined sensitive Attribute with explicit Presence Filter syntax without the presence of obfuscation.
							suspiciousAttributePresenceFilterMatchArr = suspiciousAttributePresenceFilterArr.Where(val => (
								string.Equals(ldapFilter.Attribute, val, StringComparison.OrdinalIgnoreCase) ||
								string.Equals(ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name, val, StringComparison.OrdinalIgnoreCase)
							)).ToList();
							if (suspiciousAttributePresenceFilterMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Presence Filter and Does Not Contain Obfuscation and Is Specific Suspicious Attribute: '{suspiciousAttributePresenceFilterMatchArr[0]}'",
										"(userPassword=*)",
										20.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_ATTRIBUTE_LOGICAL_PRESENCE_FILTER_WITH_OBFUSCATION:
							// Break if ComparisonOperator is not '>=' or '<=' Range ComparisonOperator.
							if (!(ldapFilter.ComparisonOperator == ">=" || ldapFilter.ComparisonOperator == "<="))
							{
								break;
							}

							// Detect any previously-defined sensitive Attribute with logical Presence Filter syntax with the
							// presence of '>=' or '<=' Range ComparisonOperator obfuscation.
							suspiciousAttributePresenceFilterMatchArr = suspiciousAttributePresenceFilterArr.Where(val => (
								string.Equals(ldapFilter.Attribute, val, StringComparison.OrdinalIgnoreCase) ||
								string.Equals(ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name, val, StringComparison.OrdinalIgnoreCase)
							)).ToList();
							if (suspiciousAttributePresenceFilterMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										//"Filter Contains Defined Attribute with Abnormal Syntax",
										$"Filter Contains Logical Presence Filter and Contains '>=' or '<=' Range ComparisonOperator Obfuscation and Is Specific Suspicious Attribute: '{suspiciousAttributePresenceFilterMatchArr[0]}'",
										"(|(userPassword>==)(userPassword<=~))",
										20.0
									)
								);
							}

							break;
						case DetectionID.SENSITIVE_ATTRIBUTE_ABNORMAL_SYNTAX:
							// Break if Attribute is undefined or not in an OID format.
							if (!(
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.IsDefined == false ||
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Format == LdapTokenFormat.OID
							))
							{
								break;
							}

							// Detect any previously-defined sensitive Attribute with abnormal Attribute syntax.
							suspiciousAttributePresenceFilterMatchArr = suspiciousAttributePresenceFilterArr.Where(val => (
								string.Equals(ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name, val, StringComparison.OrdinalIgnoreCase)
							)).ToList();
							if (suspiciousAttributePresenceFilterMatchArr.Count > 0)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Abnormal Syntax for Specific Suspicious Attribute: '{suspiciousAttributePresenceFilterMatchArr[0]}'",
										"(2.5.4.35=*)",
										20.0
									)
								);
							}

							break;
						case DetectionID.SPECIFIC_BITWISE_ADDEND_FOR_DEFINED_ATTRIBUTE_USERACCOUNTCONTROL:
							if (
								string.Equals(ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.Name, "userAccountControl") &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.BitwiseDict[128] == true
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Filter Contains Defined Attribute 'userAccountControl' With Specific Bitwise Addend 'ENCRYPTED_TEXT_PWD_ALLOWED' ('128') In Actual Value: '{ldapFilter.Value}'",
										"(userAccountControl:1.2.840.113556.1.4.804:=65929)",
										20.0
									)
								);
							}

							break;
						case DetectionID.LOGICALLY_EXCLUDED_FILTER_EXTENSIBLEMATCHFILTER_OR_EXCESSIVE_BITWISE_ADDEND_COUNT:
							if (
								ldapFilter.Context.BooleanOperator.LogicalFilterInclusion == false &&
								ldapFilter.TokenDict[LdapTokenType.ExtensibleMatchFilter]?.Context.ExtensibleMatchFilter.Name == "LDAP_MATCHING_RULE_BIT_OR" &&
								ldapFilter.TokenDict[LdapTokenType.Attribute]?.Context.Attribute.ValueFormat == LdapTokenFormat.Bitwise &&
								ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.BitwiseAddend.Count >= 3
							)
							{
								// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
								detectionHitList.Add(
									new Detection(
										ldapFilter,
										"Official_MaLDAPtive_Ruleset",
										new DateTime(2024, 07, 04),
										curDetectionID,
										$"Logically Excluded Filter Containing OR ExtensibleMatchFilter for Bitwise Attribute Containing Excessive Count ('{ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.BitwiseAddend.Count}') of Bitwise Addends: {string.Join(", ", ldapFilter.TokenDict[LdapTokenType.Value]?.Context.Value.BitwiseAddend.Select(addend => $"'{addend}'"))}",
										"(!(userAccountControl:1.2.840.113556.1.4.804:=65929))",
										20.0
									)
								);
							}

							break;
					}
				}
			}

			// Order final list of Detection hits by Start index property.
			detectionHitList = detectionHitList.OrderBy(detection => detection.Start).ToList();

			// Return current list of Detection hits for current LDAP SearchFilter.
			return detectionHitList;
        }

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvilInFilter(LdapBranch ldapBranch, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = ldapBranch.Content;

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvilInFilter(
					LdapParser.ToFilter(
						LdapParser.ToTokenEnriched(
							LdapParser.Tokenize(ldapSearchFilter)
						)
					)
                ,detectionIDList);
		}

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInFilter(List<LdapTokenEnriched> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInFilter(
                    LdapParser.ToFilter(ldapTokens)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInFilter(List<LdapToken> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInFilter(
					LdapParser.ToFilter(
						LdapParser.ToTokenEnriched(ldapTokens)
					)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInFilter(string ldapSearchFilter, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInFilter(
					LdapParser.ToFilter(
						LdapParser.ToTokenEnriched(
							LdapParser.Tokenize(ldapSearchFilter)
						)
					)
                ,detectionIDList);
        }

        /// <summary>
        /// This method returns list of Detection objects for each Detection "hit" occurring for
		/// every recursively traversed section of input LDAP SearchFilter.
        /// </summary>
        public static List<Detection> FindEvilInBranch(LdapBranch ldapBranch, List<DetectionID> detectionIDList = null)
        {
			// Return empty list of Detections if input ldapBranch has no child branches.
            if (ldapBranch.Branch.Count == 0)
            {
				return new List<Detection>();
            }

			// Create bools to track if current function invocation is recursive as well as placeholder bools
			// for nested FilterList and Filter LdapBranches.
			bool isRecursiveFunctionInvocation = ldapBranch.Depth == 0 && ldapBranch.Start == 0 ? false : true;
			bool isRecursiveFilterListBranch;
			bool isRecursiveFilterBranch;

            // Create new list of Detections to store next recursive set of Detections for input ldapBranch.
            List<Detection> detectionHitList = new List<Detection>();

			// If input detectionIDList is null or empty then instantiate it with all valid DetectionID values.
			if (detectionIDList == null)
			{
				detectionIDList = new List<DetectionID>((DetectionID[])Enum.GetValues(typeof(DetectionID)));
			}

			// Extract list of branches from input ldapBranch, separately extracting nested LdapToken and
			// LdapBranch object(s) along with potential leading BooleanOperator LdapToken.
			List<object> ldapTokensAndBranchesMerged = ldapBranch.Branch;
			List<LdapTokenEnriched> nestedLdapTokenArr = ldapTokensAndBranchesMerged.Where(obj => obj is LdapTokenEnriched).Select(obj => obj as LdapTokenEnriched).ToList();
			List<LdapBranch> nestedLdapBranchArr = ldapTokensAndBranchesMerged.Where(obj => obj is LdapBranch).Select(obj => obj as LdapBranch).ToList();
			LdapTokenEnriched ldapBranchBooleanOperator = nestedLdapTokenArr?.FirstOrDefault(token => token.Type == LdapTokenType.BooleanOperator);

			// Iterate over each merged LdapTokenEnriched and/or LdapBranch object from extracted list of branches.
            for (int i = 0; i < ldapTokensAndBranchesMerged.Count; i++)
            {
				// Skip any potential non-LdapBranch objects.
				if (ldapTokensAndBranchesMerged[i] is not LdapBranch)
				{
					continue;
				}

				// Explicitly cast current object to LdapBranch.
				LdapBranch curLdapBranch = ldapTokensAndBranchesMerged[i] as LdapBranch;

                // Evaluate detection logic separately based on current LdapBranch Type.
				switch (curLdapBranch.Type)
                {
					case LdapBranchType.FilterList:
						// Recursively search current LdapBranch, appending any potential Detections
						// to list of Detections for current LDAP SearchFilter.
						detectionHitList.AddRange(
							FindEvilInBranch(curLdapBranch, detectionIDList)
						);

						// Update placeholder bool for recursive nature of current FilterList LdapBranch.
						isRecursiveFilterListBranch = isRecursiveFunctionInvocation == false && curLdapBranch.Depth == 0 ? false : true;

                        // Extract potential contextual BooleanOperator values for trailing adjacent
						// same-value BooleanOperator scenarios.
						string filterListBooleanOperatorTokenListStr = curLdapBranch.Context.BooleanOperator?.FilterListBooleanOperatorTokenList?.Count > 0 ? string.Join("", curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Select(boolean => boolean.Content).ToList()) + curLdapBranch.BooleanOperator : "";
						int filterListBooleanOperatorAdjacentSuffixCount = filterListBooleanOperatorTokenListStr.Length > 0 ? (filterListBooleanOperatorTokenListStr.Length - filterListBooleanOperatorTokenListStr.TrimEnd(filterListBooleanOperatorTokenListStr[filterListBooleanOperatorTokenListStr.Length - 1]).Length) : 0;

						// Track the Depths of all BooleanOperators in the current LdapBranch's BooleanOperator context chain for display purposes.
						List<int> filterListBooleanOperatorTokenListDepths = new List<int>();
						if (curLdapBranch.Context.BooleanOperator?.FilterListBooleanOperatorTokenList?.Count > 0)
						{
							filterListBooleanOperatorTokenListDepths.AddRange(curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Select(boolean => boolean.Depth).ToList());
						}
						// If current LdapBranch contains a BooleanOperator then add its Depth to filterListBooleanOperatorTokenListDepths.
						if (curLdapBranch.BooleanOperator != null)
						{
							filterListBooleanOperatorTokenListDepths.Add(curLdapBranch.Depth + 1);
						}

						// Iterate over and evaluate each defined DetectionID for current FilterList LdapBranch.
						foreach (DetectionID curDetectionID in detectionIDList)
						{
							switch (curDetectionID)
							{
								case DetectionID.CONTEXT_SEARCHFILTER_EXCESSIVE_LENGTH:
									if (
										isRecursiveFilterListBranch == false &&
										curLdapBranch.Length >= 1000 &&
										// Remove FPs for large "flat" SearchFilters by requiring some amount of Depth.
										curLdapBranch.DepthMax >= 10
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Excessive Length of Entire SearchFilter ('{curLdapBranch.Length}')",
												"(&(|(!(&(|(!((((((co=Albania))))))))))))",
												50.0 * (curLdapBranch.Length / 1000)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_FILTER_EXCESSIVE_MAX_DEPTH:
									if (
										isRecursiveFilterListBranch == false &&
										curLdapBranch.DepthMax >= 10
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Excessive Max Depth of Filter LdapBranch ('{curLdapBranch.DepthMax}')",
												"((((((((((((co=Albania))))))))))))",
												10.0 * curLdapBranch.DepthMax
											)
										);
									}

									break;
								case DetectionID.CONTEXT_FILTER_BOOLEANOPERATOR_EXCESSIVE_MAX_COUNT:
									if (
										isRecursiveFilterListBranch == false &&
										curLdapBranch.BooleanOperatorCountMax >= 8
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Excessive Max Count of BooleanOperator Context Chain of Filter LdapBranch ('{curLdapBranch.BooleanOperatorCountMax}')",
												"(|(|(|(&(|(!(&(|(!(co=Albania))))))))))",
												10.0 * curLdapBranch.BooleanOperatorCountMax
											)
										);
									}

									break;
								case DetectionID.CONTEXT_FILTERLIST_BRANCH_WITH_GAPPED_BOOLEANOPERATOR:
									if (curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance >= 3)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"FilterList LdapBranch With Gapped BooleanOperator Context Chain (gap distance='{curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance}') At Depth '{curLdapBranch.Depth}'",
												"(&((((|(co=Albania))))))",
												10.0 * curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance
											)
										);
									}

									break;
								case DetectionID.CONTEXT_FILTERLIST_BRANCH_WITH_BOOLEANOPERATOR_CLOSING_GAPPED_BOOLEANOPERATOR:
									if (
										curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance >= 3 &&
										curLdapBranch.BooleanOperator != null
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"FilterList LdapBranch With BooleanOperator Closing Gapped BooleanOperator Context Chain (gap distance='{curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance}') At Depth '{curLdapBranch.Depth}'",
												"(&((((|(co=Albania))))))",
												10.0 * curLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorDistance
											)
										);
									}

									break;
								case DetectionID.LOGICALLY_EXCLUDED_FILTERLIST_BRANCH_NOT_AND:
									if (
										curLdapBranch.Context.BooleanOperator.LogicalFilterInclusion == false &&
										curLdapBranch.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!&" &&
										curLdapBranch.Depth > 3
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Logically Excluded FilterList LdapBranch Via '!&' (NOT-AND) At Depth '{curLdapBranch.Depth}'",
												"(!(&(!(co=Albania))(!(l=Kukes))))",
												22.5
											)
										);
									}

									break;
								case DetectionID.LOGICALLY_EXCLUDED_FILTERLIST_BRANCH_NOT_OR:
									if (
										curLdapBranch.Context.BooleanOperator.LogicalFilterInclusion == false &&
										curLdapBranch.Context.BooleanOperator.LogicalFilterListBooleanOperator == "!|"
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Logically Excluded FilterList LdapBranch Via '!|' (NOT-OR) At Depth '{curLdapBranch.Depth}'",
												"(!(|(!(co=Albania))(!(l=Kukes))))",
												22.5
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_AND_COUNT:
									if (
										curLdapBranch.BooleanOperator == "&" &&
										filterListBooleanOperatorAdjacentSuffixCount >= 3 &&
										// Remove FPs by requiring some amount of Depth.
										curLdapBranch.Depth >= 6
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (AND) Count ('{filterListBooleanOperatorAdjacentSuffixCount}') At the Following Depths: {string.Join(", ", filterListBooleanOperatorTokenListDepths.TakeLast(filterListBooleanOperatorAdjacentSuffixCount).Select(depth => $"'{depth}'").ToList())}",
												"(|(&(((&(&(&(co=Albania))))))))",
												10.0 * (filterListBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_OR_COUNT:
									if (
										curLdapBranch.BooleanOperator == "|" &&
										filterListBooleanOperatorAdjacentSuffixCount >= 3 &&
										// Remove FPs by requiring some amount of Depth.
										curLdapBranch.Depth >= 6
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (OR) Count ('{filterListBooleanOperatorAdjacentSuffixCount}') At the Following Depths: {string.Join(", ", filterListBooleanOperatorTokenListDepths.TakeLast(filterListBooleanOperatorAdjacentSuffixCount).Select(depth => $"'{depth}'").ToList())}",
												"(&(|(((|(|(|(co=Albania))))))))",
												10.0 * (filterListBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_NOT_COUNT:
									if (
										curLdapBranch.BooleanOperator == "!" &&
										(
											filterListBooleanOperatorAdjacentSuffixCount >= 3 ||
											(
												filterListBooleanOperatorAdjacentSuffixCount >= 2 &&
												curLdapBranch.Depth >= 10
											)
										)
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												curLdapBranch,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (NOT) Count ('{filterListBooleanOperatorAdjacentSuffixCount}') At the Following Depths: {string.Join(", ", filterListBooleanOperatorTokenListDepths.TakeLast(filterListBooleanOperatorAdjacentSuffixCount).Select(depth => $"'{depth}'").ToList())}",
												"(!((!(co=Albania))))",
												20.0 * (filterListBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
							}
						}

						break;
					case LdapBranchType.Filter:
						// Explicitly cast current LdapBranch's nested Branch property to LdapFilter.
						LdapFilter ldapFilter = curLdapBranch.Branch[0] as LdapFilter;

						// Update placeholder bool for recursive nature of current Filter LdapBranch.
						isRecursiveFilterBranch = isRecursiveFunctionInvocation == false && curLdapBranch.Depth == 0 ? false : true;

                        // Extract potential contextual BooleanOperator values for trailing adjacent
						// same-value BooleanOperator scenarios.
						string filterBooleanOperatorTokenListStr = "";
						filterBooleanOperatorTokenListStr = ldapFilter.Context.BooleanOperator?.FilterListBooleanOperatorTokenList?.Count > 0 ? filterBooleanOperatorTokenListStr + string.Join("", ldapFilter.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Select(boolean => boolean.Content).ToList()) : filterBooleanOperatorTokenListStr;
						filterBooleanOperatorTokenListStr = ldapFilter.Context.BooleanOperator?.FilterBooleanOperatorTokenList?.Count > 0 ? filterBooleanOperatorTokenListStr + string.Join("", ldapFilter.Context.BooleanOperator.FilterBooleanOperatorTokenList.Select(boolean => boolean.Content).ToList()) : filterBooleanOperatorTokenListStr;
						int filterBooleanOperatorAdjacentSuffixCount = filterBooleanOperatorTokenListStr.Length > 0 ? (filterBooleanOperatorTokenListStr.Length - filterBooleanOperatorTokenListStr.TrimEnd(filterBooleanOperatorTokenListStr[filterBooleanOperatorTokenListStr.Length - 1]).Length) : 0;

						// Iterate over and evaluate each defined DetectionID for current Filter LdapBranch.
						foreach (DetectionID curDetectionID in detectionIDList)
						{
							switch (curDetectionID)
							{
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_AND_COUNT:
									if (
										ldapFilter.BooleanOperator == "&" &&
										filterBooleanOperatorAdjacentSuffixCount >= 2
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												ldapFilter,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (AND) Count ('{filterBooleanOperatorAdjacentSuffixCount}') (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
												"(&(&co=Albania))",
												20.0 * (filterBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_OR_COUNT:
									if (
										ldapFilter.BooleanOperator == "|" &&
										filterBooleanOperatorAdjacentSuffixCount >= 2
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												ldapFilter,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (OR) Count ('{filterBooleanOperatorAdjacentSuffixCount}') (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
												"(|(|co=Albania))",
												20.0 * (filterBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_NOT_COUNT:
									if (
										ldapFilter.BooleanOperator == "!" &&
										filterBooleanOperatorAdjacentSuffixCount >= 2
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												ldapFilter,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"Adjacent Repeating FilterList BooleanOperators (NOT) Count ('{filterBooleanOperatorAdjacentSuffixCount}') (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
												"(!(!co=Albania))",
												30.0 * (filterBooleanOperatorAdjacentSuffixCount - 1)
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_AND_MODIFYING_SINGLE_FILTER:
									if (
										nestedLdapBranchArr.Count == 1 &&
										ldapBranch.BooleanOperator == "&" &&
										// Remove FPs by requiring some amount of Depth.
										ldapBranch.Depth >= 5
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												ldapFilter,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												"BooleanOperator (AND) Modifying Only a Single Filter LdapBranch (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
												"((&(co=Albania)))",
												17.5
											)
										);
									}

									break;
								case DetectionID.CONTEXT_BOOLEANOPERATOR_OR_MODIFYING_SINGLE_FILTER:
									if (
										nestedLdapBranchArr.Count == 1 &&
										ldapBranch.BooleanOperator == "|" &&
										// Remove FPs by requiring some amount of Depth.
										ldapBranch.Depth >= 5
									)
									{
										// Generate new Detection hit and append to list of Detections for current LDAP SearchFilter.
										detectionHitList.Add(
											new Detection(
												ldapFilter,
												"Official_MaLDAPtive_Ruleset",
												new DateTime(2024, 07, 04),
												curDetectionID,
												$"BooleanOperator (OR) Modifying Only a Single Filter LdapBranch (Attribute='{ldapFilter.Attribute}', Depth='{ldapFilter.Depth}')",
												"((|(co=Albania)))",
												17.5
											)
										);
									}

									break;
							}
						}

						break;
				}
			}

			// Order final list of Detection hits by Start index property.
			if (isRecursiveFunctionInvocation == false)
			{
				detectionHitList = detectionHitList.OrderBy(detection => detection.Start).ToList();
			}

			// Return current list of Detection hits for current LDAP SearchFilter.
			return detectionHitList;
        }

		// Do not overload for List<LdapFilter> format since it intentionally drops non-Filter tokens.

		// Overloaded method to handle multiple input formats.
		public static List<Detection> FindEvilInBranch(List<object> ldapTokensAndFiltersMerged, List<DetectionID> detectionIDList = null)
		{
			// Extract entire LDAP SearchFilter as single string.
			string ldapSearchFilter = string.Join("", ldapTokensAndFiltersMerged.Select(obj => obj is LdapTokenEnriched ? (obj as LdapTokenEnriched).Content : (obj as LdapFilter).Content).ToList());

			// Return list of Detections for input LDAP SearchFilter.
			return LdapParser.FindEvilInBranch(
                    LdapParser.ToBranch(
						LdapParser.ToFilter(
							LdapParser.ToTokenEnriched(
								LdapParser.Tokenize(ldapSearchFilter)
							)
						)
					)
                ,detectionIDList);
		}

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInBranch(List<LdapTokenEnriched> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInBranch(
                    LdapParser.ToBranch(
                    	LdapParser.ToFilter(ldapTokens)
					)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInBranch(List<LdapToken> ldapTokens, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInBranch(
                    LdapParser.ToBranch(
						LdapParser.ToFilter(
							LdapParser.ToTokenEnriched(ldapTokens)
						)
					)
                ,detectionIDList);
        }

        // Overloaded method to handle multiple input formats.
        public static List<Detection> FindEvilInBranch(string ldapSearchFilter, List<DetectionID> detectionIDList = null)
        {
			// Return list of Detections for input LDAP SearchFilter.
            return LdapParser.FindEvilInBranch(
                    LdapParser.ToBranch(
						LdapParser.ToFilter(
							LdapParser.ToTokenEnriched(
								LdapParser.Tokenize(ldapSearchFilter)
							)
						)
					)
                ,detectionIDList);
        }

        /// <summary>
        /// This method returns DetectionSummary object consolidating and summarizing all input Detection objects
		/// returned by FindEvil* methods for input LDAP SearchFilter.
        /// </summary>
        public static DetectionSummary ToEvilSummary(List<Detection> detections, string searchFilter)
        {
			// Return empty DetectionSummary if input detections is empty.
            if (detections.Count == 0)
            {
				return new DetectionSummary(searchFilter);
            }

			// Calculate total score from input detections.
			double totalScore = detections.Sum(detection => detection.Score);

			// Extract unique lists of DetectionID and Name property values from input detections.
			//List<DetectionID> distinctDetectionIDs = detections.DistinctBy(detection => (detection.ID as DetectionID)).ToList();
			List<DetectionID> distinctDetectionIDs = detections.Select(detection => detection.ID).DistinctBy(id => id).ToList();
			List<string> distinctDetectionNames = detections.Select(detection => detection.Name).DistinctBy(name => name).ToList();

			// Create and return DetectionSummary object for input searchFilter.
			return new DetectionSummary(
				totalScore,
				detections,
				distinctDetectionIDs,
				distinctDetectionNames,
				searchFilter
			);
        }
    }

    /// <summary>
    /// This enum defines all potential LDAP token types.
	/// </summary>
    public enum LdapTokenType
    {
        Undefined = 0,
        GroupStart = 1,
        GroupEnd = 2,
        BooleanOperator = 3,
        Attribute = 4,
        ExtensibleMatchFilter = 5,
        ComparisonOperator = 6,
        Value = 7,
        Whitespace = 8,
		// CommaDelimiter only used for RDN Subtype.
        CommaDelimiter = 9,
    };

    /// <summary>
    /// This enum defines all potential LDAP token subtypes.
	/// </summary>
    public enum LdapTokenSubType
    {
        Undefined = 0,
        RDN = 1,
    };

    /// <summary>
    /// This enum defines all potential LDAP token scopes.
	/// </summary>
    public enum LdapTokenScope
    {
        Undefined = 0,
        Filter = 1,
        FilterList = 2,
        BooleanOperator = 3,
        NA = 4,
    };

    /// <summary>
    /// This enum defines all potential LDAP token formats.
	/// </summary>
    public enum LdapTokenFormat
    {
        Undefined = 0,
        NA = 1,
        String = 2,
        OID = 3,
        Bitwise = 4,
        Boolean = 5,
        DateTime = 6,
        IntTimeInterval = 7,
        DNWithBinary = 8,
        DNString = 9,
        SID = 10,
        IntEnumeration = 11,
		HexObjectReplicaLink = 12,
		StringObjectIdentifier = 13,
		StringUnicode = 14,
		StringIA5 = 15,
		StringNTSecurityDescriptor = 16,
		StringTeletex = 17,
		StringNumeric = 18,
		StringObjectAccessPoint = 19,
		StringObjectPresentationAddress = 20,
    };

	/// <summary>
    /// This enum defines all potential parsed character formats for LdapValueParsed class.
	/// </summary>
    public enum LdapValueParsedFormat
    {
        Undefined = 0,
        Default = 1,
        Protected = 2,
        Hex = 3,
        EscapedKnown = 4,
        EscapedUnknown = 5,
    };

    /// <summary>
    /// This enum defines all potential character classes for CharContext class.
	/// </summary>
	public enum CharClass
    {
        Undefined = 0,
        Alpha = 1,
		Num = 2,
		Special = 3,
		ControlC0 = 4,
		ControlC1 = 5,
    };

    /// <summary>
    /// This enum defines all potential character cases for CharContext class.
	/// </summary>
	public enum CharCase
    {
        Undefined = 0,
        NA = 1,
		Upper = 2,
		Lower = 3,
    };

    /// <summary>
    /// This enum defines all potential LDAP branch types.
	/// </summary>
    public enum LdapBranchType
    {
        Filter = 0,
        FilterList = 1,
    };

    /// <summary>
    /// This enum defines all potential LDAP Attribute ADS Types for LdapAttributeContext class.
	/// </summary>
    public enum LdapAttributeSyntaxADSType
    {
        Undefined = 0,
        Boolean = 1,
        CaseIgnoreString = 2,
        DNString = 3,
        DNWithBinary = 4,
        Integer = 5,
        LargeInteger = 6,
        NTSecurityDescriptor = 7,
        NumericString = 8,
        OctetString = 9,
        PrintableString = 10,
        UTCTime = 11,
    };

    /// <summary>
    /// This enum defines all potential LDAP Attribute SDS Types for LdapAttributeContext class.
	/// </summary>
    public enum LdapAttributeSyntaxSDSType
    {
        Undefined = 0,
        Boolean = 1,
        ByteArray = 2,
        DateTime = 3,
        IADsDNWithBinary = 4,
        IADsLargeInteger = 5,
        IADsSecurityDescriptor = 6,
        Int32 = 7,
        String = 8,
    };

    /// <summary>
    /// This enum defines all potential LDAP Attribute MAPI Types for LdapAttributeContext class.
	/// </summary>
    public enum LdapAttributeSyntaxMAPIType
    {
        Undefined = 0,
        Binary = 1,
        Boolean = 2,
        Long = 3,
        Object = 4,
        Systime = 5,
        TString = 6,
    };

    /// <summary>
    /// This enum defines all potential LDAP Attribute Syntax Titles for LdapAttributeContext class.
	/// </summary>
    public enum LdapAttributeSyntaxTitle
    {
        Undefined = 0,
        Boolean = 1,
        Enumeration = 2,
        Interval = 3,
        Object_Access_Point = 4,
        Object_DN_Binary = 5,
        Object_DS_DN = 6,
        Object_Presentation_Address = 7,
        Object_Replica_Link = 8,
        String_Generalized_Time = 9,
        String_IA5 = 10,
        String_NT_Sec_Desc = 11,
        String_Numeric = 12,
        String_Object_Identifier = 13,
        String_Sid = 14,
        String_Teletex = 15,
        String_Unicode = 16,
    };

    /// <summary>
	/// This enum defines all potential parsed SearchFilter data formats.
	/// </summary>
    public enum LdapFormat
    {
		String = 0,
		LdapToken = 1,
		LdapTokenEnriched = 2,
		LdapFilter = 3,
		LdapFilterMerged = 4,
		LdapBranch = 5,
    };

    /// <summary>
    /// This enum defines all potential LDAP Detection IDs.
	/// </summary>
    public enum DetectionID
    {
		// DetectionIDs for FindEvilInTokenEnriched method.
		CONTEXT_BOOLEANOPERATOR_EXCESSIVE_COUNT,
		CONTEXT_BOOLEANOPERATOR_NONSHALLOW_EXCESSIVE_COUNT,
		CONTEXT_EXTENSIBLEMATCHFILTER_EXCESSIVE_COUNT,
		CONTEXT_WHITESPACE_EXCESSIVE_COUNT,
		CONTEXT_LARGE_WHITESPACE_EXCESSIVE_COUNT,
		CONTEXT_WHITESPACE_UNCOMMON_NEIGHBOR_EXCESSIVE_COUNT,
		//
		// DetectionIDs for FindEvilInFilter method.
		CONTEXT_FILTER_EXCESSIVE_COUNT,
		CONTEXT_FILTER_NONSHALLOW_EXCESSIVE_COUNT,
		CONTEXT_LOGICALLY_EXCLUDED_FILTER_EXCESSIVE_COUNT,
		CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_NOT_EXCESSIVE_COUNT,
		CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_NOT_NONSHALLOW_EXCESSIVE_COUNT,
		CONTEXT_UNDEFINED_ATTRIBUTE_EXCESSIVE_DISTINCT_COUNT,
		CONTEXT_UNDEFINED_ATTRIBUTE_NONSHALLOW_EXCESSIVE_DISTINCT_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_EXCLUDED_FILTER_EXCESSIVE_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_EXCLUDED_FILTER_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE_EXCESSIVE_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE_EXCESSIVE_COUNT,
		CONTEXT_COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE_EXCESSIVE_DISTINCT_ATTRIBUTE_COUNT,
		CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_AND,
		CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_OR,
		FILTER_BRANCH_WITH_GAPPED_BOOLEANOPERATOR,
		LOGICALLY_INCLUDED_FILTER_BRANCH_NOT_AND,
		LOGICALLY_INCLUDED_FILTER_BRANCH_NOT_OR,
		LOGICALLY_EXCLUDED_FILTER_BRANCH_NOT_AND,
		LOGICALLY_EXCLUDED_FILTER_BRANCH_NOT_OR,
		CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_EXCESSIVE_COUNT,
		CONTEXT_FILTER_EXCESSIVE_DEPTH,
		UNDEFINED_EXTENSIBLEMATCHFILTER,
		UNDEFINED_ATTRIBUTE_INVALID_SPECIAL_CHARS,
		DEFINED_ATTRIBUTE_ABNORMAL_SYNTAX,
		DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_OID_PREFIX,
		DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_ZEROS,
		COMPARISONOPERATOR_RANGE_EXCLUDED,
		COMPARISONOPERATOR_RANGE_DEFINED_BITWISE_ATTRIBUTE,
		COMPARISONOPERATOR_RANGE_DEFINED_BYTEARRAY_ATTRIBUTE,
		SPECIFIC_ATTRIBUTE_ANR_OID_SYNTAX,
		RDN_ATTRIBUTE_WITH_OID_SYNTAX,
		RDN_ATTRIBUTE_WITH_HEX_ENCODING,
		RDN_COMPARISONOPERATOR_WITH_HEX_ENCODING,
		RDN_COMMADELIMITER_WITH_HEX_ENCODING,
		RDN_WHITESPACE_WITH_HEX_ENCODING,
		RDN_VALUE_ENCAPSULATED_WITH_DOUBLE_QUOTES,
		RDN_EXCESSIVE_WHITESPACE,
		INT_VALUE_WITH_PREPENDED_ZERO,
		INT_VALUE_WITH_PREPENDED_ZEROES,
		DATETIME_VALUE_WITH_OBFUSCATED_MILLISECONDS,
		VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS,
		VALUE_WITH_EXCESSIVE_WILDCARD_COUNT,
		SENSITIVE_VALUE_MATCHED_WITH_WILDCARD,
		SENSITIVE_VALUE_WITH_HEX_ENCODING,
		SENSITIVE_VALUE_WITHOUT_OBFUSCATION_APPROXIMATELY_EQUAL_COMPARISONOPERATOR,
		SENSITIVE_VALUE_WITHOUT_OBFUSCATION,
		SENSITIVE_VALUE_WITHOUT_OBFUSCATION_WITH_SPECIFIC_ATTRIBUTE_ANR,
		SENSITIVE_VALUE_SUBSTRING_WITH_LOGICAL_WILDCARD_WITH_SPECIFIC_ATTRIBUTE_ANR,
		SENSITIVE_VALUE_SUBSTRING_WITH_WILDCARD_WITH_SPECIFIC_ATTRIBUTE_ANR,
		SENSITIVE_ATTRIBUTE_PRESENCE_FILTER,
		SENSITIVE_ATTRIBUTE_LOGICAL_PRESENCE_FILTER_WITH_OBFUSCATION,
		SENSITIVE_ATTRIBUTE_ABNORMAL_SYNTAX,
		SPECIFIC_BITWISE_ADDEND_FOR_DEFINED_ATTRIBUTE_USERACCOUNTCONTROL,
		LOGICALLY_EXCLUDED_FILTER_EXTENSIBLEMATCHFILTER_OR_EXCESSIVE_BITWISE_ADDEND_COUNT,
		//
		// DetectionIDs for FindEvilInBranch method.
		// LdapBranch-specific Detection IDs.
		CONTEXT_SEARCHFILTER_EXCESSIVE_LENGTH,
		CONTEXT_FILTER_EXCESSIVE_MAX_DEPTH,
		CONTEXT_FILTER_BOOLEANOPERATOR_EXCESSIVE_MAX_COUNT,
		CONTEXT_FILTERLIST_BRANCH_WITH_GAPPED_BOOLEANOPERATOR,
		CONTEXT_FILTERLIST_BRANCH_WITH_BOOLEANOPERATOR_CLOSING_GAPPED_BOOLEANOPERATOR,
		LOGICALLY_EXCLUDED_FILTERLIST_BRANCH_NOT_AND,
		LOGICALLY_EXCLUDED_FILTERLIST_BRANCH_NOT_OR,
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_AND_COUNT,
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_OR_COUNT,
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_NOT_COUNT,
		// LdapFilter-specific Detection IDs.
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_AND_COUNT,
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_OR_COUNT,
		CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_NOT_COUNT,
		CONTEXT_BOOLEANOPERATOR_AND_MODIFYING_SINGLE_FILTER,
		CONTEXT_BOOLEANOPERATOR_OR_MODIFYING_SINGLE_FILTER,
    };
}