.method private isNetworkAvailable()Z
    .registers 2

    # const-string v0, "connectivity"

    # .line 139
    # invoke-virtual {p0, v0}, Lcom/axinom/drm/sample/activity/SampleChooserActivity;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    # move-result-object v0

    # check-cast v0, Landroid/net/ConnectivityManager;

    # if-eqz v0, :cond_f

    # .line 142
    # invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    # move-result-object v0

    # goto :goto_10

    # :cond_f
    # const/4 v0, 0x0

    # :goto_10
    # if-eqz v0, :cond_1a

    # .line 144
    # invoke-virtual {v0}, Landroid/net/NetworkInfo;->isConnected()Z

    # move-result v0

    # if-eqz v0, :cond_1a

    # const/4 v0, 0x1

    # goto :goto_1b

    # :cond_1a
    # const/4 v0, 0x0

    # :goto_1b

    const/4 v0, 0x1

    return v0
.end method
