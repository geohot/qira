<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 
  <xsl:template match="/" mode="dictionaries">

    <xsl:text>&#10;#&#10;# dictionary rules&#10;#&#10;&#10;</xsl:text>
  
    <!-- Set all dictionary source lists empty -->
    <xsl:for-each select="//dictionary">
     <xsl:sort select="@name"/>
    
     <xsl:variable name="conditions">
      <xsl:text>0</xsl:text>
      <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
       <xsl:call-template name="resolve-condition">
        <xsl:with-param select="@condition" name="expression"/>
       </xsl:call-template>
      </xsl:for-each>
     </xsl:variable>
     
    <xsl:if test="$conditions = 0">
     
     <xsl:if test="not(preceding::dictionary/@name = @name)">
      <xsl:value-of select="@name"/>
      <xsl:text>-DICTIONARY :=&#10;</xsl:text>
     </xsl:if>
     </xsl:if>
    </xsl:for-each>
    
    <!-- Add all forth source files to their dictionaries -->
    <xsl:for-each select="//dictionary/object">
    
     <xsl:variable name="path">
      <xsl:for-each select="ancestor::build">
       <xsl:call-template name="get-dirname">
        <xsl:with-param select="@base" name="path"/>
       </xsl:call-template>
      </xsl:for-each>
     </xsl:variable>
 
     <xsl:variable name="conditions">
      <xsl:text>0</xsl:text>
      <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
       <xsl:call-template name="resolve-condition">
        <xsl:with-param select="@condition" name="expression"/>
       </xsl:call-template>
      </xsl:for-each>
     </xsl:variable>
 
     <xsl:variable name="dictname">
      <xsl:value-of select="parent::*/@name"/>
     </xsl:variable>

     <xsl:if test="$conditions=0">

      <xsl:variable name="source"><xsl:value-of select="@source" /></xsl:variable>

      <!-- Handle just Forth source, not FCode -->
      <xsl:if test="not(@target = 'fcode')">
       <xsl:value-of select="$dictname"/><xsl:text>-DICTIONARY:=$(</xsl:text>
       <xsl:value-of select="$dictname"/><xsl:text>-DICTIONARY) </xsl:text>

       <xsl:value-of select="$path"/>
       <xsl:value-of select="$source"/>
       <xsl:text>&#10;</xsl:text>
      </xsl:if>

     </xsl:if>
    </xsl:for-each>
    
    <xsl:text>&#10;&#10;</xsl:text>

    <!-- Create targets for all dictionaries -->
    <xsl:for-each select="//dictionary">
    <xsl:sort select="@name"/>

     <xsl:variable name="outer-conditions">
      <xsl:text>0</xsl:text>
      <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
       <xsl:call-template name="resolve-condition">
        <xsl:with-param select="@condition" name="expression"/>
       </xsl:call-template>
      </xsl:for-each>
     </xsl:variable>
     
    <xsl:if test="$outer-conditions = 0">
    
    <xsl:if test="not(preceding::dictionary/@name = @name)">
     <xsl:variable name="name"><xsl:value-of select="@name"/></xsl:variable>
     <xsl:variable name="init">
      <xsl:value-of select="(//dictionary[@name=$name]/attribute::init)[last()]"/>
     </xsl:variable>
     <!-- dictionary name and dependencies -->
     <xsl:text>$(ODIR)/</xsl:text>
     <xsl:value-of select="@name"/><xsl:text>.dict: $(</xsl:text>
     <xsl:value-of select="@name"/>
     <xsl:text>-DICTIONARY) $(ODIR)/forthstrap</xsl:text>
     <xsl:if test="$init!=''">
      <xsl:text> $(ODIR)/</xsl:text><xsl:value-of select="$init"/><xsl:text>.dict</xsl:text>
     </xsl:if>

     <!-- Check for Fcode dependency -->
     <xsl:for-each select="object[@target = 'fcode']">

      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>

      <xsl:if test="$conditions = 0">

       <xsl:text> $(ODIR)/</xsl:text>
       <xsl:value-of select="@source"/>

      </xsl:if>
     </xsl:for-each>

     <xsl:text>&#10;</xsl:text>
     <!-- rule -->
     <xsl:text>&#9;$(call quiet-command,$(ODIR)/forthstrap</xsl:text>
     <xsl:for-each select="//dictionary[@name = @name]">
 
      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
     
      <xsl:variable name="path">
       <xsl:for-each select="ancestor::build">
        <xsl:call-template name="get-dirname">
         <xsl:with-param select="@base" name="path"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
      
      <xsl:if test="$conditions = 0">
       <xsl:text> -I</xsl:text>
       <xsl:text>$(SRCDIR)/</xsl:text>
       <xsl:value-of select="$path"/>
      </xsl:if>
     </xsl:for-each>

     <!-- needed to locate files with full path -->
     <xsl:text> -I$(SRCDIR)</xsl:text>
     <!-- needed to include config and build date -->
     <xsl:text> -I$(ODIR)/forth</xsl:text>
     
     <xsl:text> -D $@</xsl:text>
     <xsl:text> -M $@.d</xsl:text>
     <xsl:if test="$init!=''">
      <xsl:text> -d $(ODIR)/</xsl:text><xsl:value-of select="$init"/><xsl:text>.dict</xsl:text>
     </xsl:if>
     <xsl:text> -c $@-console.log</xsl:text>
     <xsl:text> $(</xsl:text>
     <xsl:value-of select="@name"/>
     <xsl:text>-DICTIONARY),"  GEN   $(TARGET_DIR)$@")&#10;&#10;</xsl:text>
    </xsl:if>
    </xsl:if>
    </xsl:for-each>
   
    <!-- Create dictionaries target containing all dictionaries -->
    <xsl:text>dictionaries: </xsl:text>
    <xsl:for-each select="//dictionary">
    <xsl:sort select="@name"/>
    
     <xsl:variable name="conditions">
      <xsl:text>0</xsl:text>
      <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
       <xsl:call-template name="resolve-condition">
        <xsl:with-param select="@condition" name="expression"/>
       </xsl:call-template>
      </xsl:for-each>
     </xsl:variable>
     
    <xsl:if test="$conditions = 0">
    
    <xsl:if test="not(preceding::dictionary/@name = @name)">
     <xsl:text>$(ODIR)/</xsl:text>
     <xsl:value-of select="@name"/><xsl:text>.dict </xsl:text>
    </xsl:if>
    </xsl:if>
    </xsl:for-each>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>
  
</xsl:stylesheet>
