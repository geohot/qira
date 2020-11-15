<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 
  <xsl:template match="/">
   <!-- add comment -->
   <xsl:text>/*&#10; * Automatically generated C config: don't edit&#10; */&#10;&#10;</xsl:text>

   <!-- scan all config options -->
   <xsl:for-each select="config/option">
    <xsl:choose>
    
     <!-- config option "boolean" -->
     <xsl:when test="@type='boolean'">
      <xsl:choose>
       <xsl:when test="@value='true'">
        <xsl:text>#define </xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text> 1</xsl:text>
       </xsl:when>
       <xsl:when test="@value='false'">
        <xsl:text>#undef  </xsl:text>
        <xsl:value-of select="@name"/>
       </xsl:when>
       <xsl:otherwise>
      <xsl:message terminate="yes">&#10;ERROR: boolean configuration option '<xsl:value-of select="@name"/>' has unsupported value '<xsl:value-of select="@type"/>' instead of [true|false].</xsl:message>
       </xsl:otherwise>
      </xsl:choose>
     </xsl:when>
     
     <!-- config option "integer" -->
     <xsl:when test="@type='integer'">
      <xsl:text>#define </xsl:text>
      <xsl:value-of select="@name"/><xsl:text> </xsl:text>
      <xsl:value-of select="@value"/>
     </xsl:when>

     <!-- config option "string" -->
     <xsl:when test="@type='string'">
      <xsl:text>#define </xsl:text>
      <xsl:value-of select="@name"/><xsl:text> </xsl:text> "<xsl:value-of select="@value"/>" </xsl:when>
    
     <!-- unsupported config option: bail out -->
     <xsl:otherwise>
      <xsl:message terminate="yes">&#10;ERROR: configuration option '<xsl:value-of select="@name"/> has unsupported type '<xsl:value-of select="@type"/>'.</xsl:message>
     </xsl:otherwise>
     
    </xsl:choose>
    
    <xsl:text>&#10;</xsl:text>
   </xsl:for-each>
   
  </xsl:template>
  
  <xsl:output method="text" indent="no" encoding="iso-8859-15"/>

</xsl:stylesheet>
