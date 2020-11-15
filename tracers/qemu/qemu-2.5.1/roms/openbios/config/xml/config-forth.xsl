<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 
  <xsl:template match="/">
   <xsl:for-each select="config/option">
    <xsl:choose>
     <xsl:when test="@type='boolean'">
      <xsl:choose>
       <xsl:when test="@value='true'">
        <xsl:text>[DEFINE] </xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>&#10;</xsl:text>
       </xsl:when>
       <xsl:when test="@value='false'">
        <!-- nothing to do -->
       </xsl:when>
       <xsl:otherwise>
        <xsl:message terminate="yes">&#10;ERROR: boolean configuration option '<xsl:value-of select="@name"/>' has unsupported value '<xsl:value-of select="@type"/>' instead of [true|false].</xsl:message>
       </xsl:otherwise>
      </xsl:choose>
     </xsl:when>
     <xsl:when test="@type='integer'">
       <!-- this makes absolutely no sense but the old code did it as well -->
       <xsl:text>[DEFINE] </xsl:text>
       <xsl:value-of select="@name"/>
       <xsl:text>&#10;</xsl:text>
     </xsl:when>
     <!-- config option "string" -->
     <xsl:when test="@type='string'">
     </xsl:when>
     <xsl:otherwise>
      <xsl:message terminate="yes">&#10;ERROR: configuration option '<xsl:value-of select="@name"/>' has unsupported type '<xsl:value-of select="@type"/>'.</xsl:message> 
     </xsl:otherwise>
    </xsl:choose>
   </xsl:for-each>
  </xsl:template>
  
  <xsl:output method="text" indent="no" encoding="iso-8859-15"/>

</xsl:stylesheet>
